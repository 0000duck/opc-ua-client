// Copyright (c) Converter Systems LLC. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.ComponentModel;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;
using Microsoft.Extensions.Logging;
using Workstation.Collections;
using Workstation.ServiceModel.Ua.Channels;

namespace Workstation.ServiceModel.Ua
{
    /// <summary>
    /// A collection of items to be monitored by the OPC UA server.
    /// </summary>
    public class Subscription : IDisposable
    {
        private const uint PublishTimeoutHint = 120 * 1000; // 2 minutes
        private const uint DiagnosticsHint = (uint)DiagnosticFlags.None;

        private static readonly ConditionalWeakTable<object, Subscription> attachedSubscriptions = new ConditionalWeakTable<object, Subscription>();

        private readonly ActionBlock<PublishResponse> actionBlock;
        private readonly IProgress<CommunicationState> progress;
        private readonly ILogger logger;
        private readonly WeakReference subscriptionRef;
        private readonly UaApplication application;

        private volatile bool isPublishing;
        private volatile UaTcpSessionChannel innerChannel;
        private volatile uint subscriptionId;
        private ErrorsContainer<string> errors;
        private PropertyChangedEventHandler propertyChanged;
        private CommunicationState state = CommunicationState.Created;
        private volatile TaskCompletionSource<bool> whenSubscribed;
        private volatile TaskCompletionSource<bool> whenUnsubscribed;
        private CancellationTokenSource stateMachineCts;
        private Task stateMachineTask;

        /// <summary>
        /// Initializes a new instance of the <see cref="Subscription"/> class.
        /// </summary>
        /// <param name="application">The session client.</param>
        /// <param name="target">The target model.</param>
        public Subscription(UaApplication application, object target)
        {
            this.application = application;
            this.subscriptionRef = new WeakReference(target);
            this.logger = this.application.LoggerFactory?.CreateLogger<Subscription>();
            //this.errors = new ErrorsContainer<string>(p => this.ErrorsChanged?.Invoke(this, new DataErrorsChangedEventArgs(p)));
            this.progress = new Progress<CommunicationState>(s => this.State = s);
            this.propertyChanged += this.OnPropertyChanged;
            //this.whenSubscribed = new TaskCompletionSource<bool>();
            //this.whenUnsubscribed = new TaskCompletionSource<bool>();
            //this.whenUnsubscribed.TrySetResult(true);

            // register the action to be run on the ui thread, if there is one.
            if (SynchronizationContext.Current != null)
            {
                this.actionBlock = new ActionBlock<PublishResponse>(pr => this.OnPublishResponse(pr), new ExecutionDataflowBlockOptions { SingleProducerConstrained = true, TaskScheduler = TaskScheduler.FromCurrentSynchronizationContext() });
            }
            else
            {
                this.actionBlock = new ActionBlock<PublishResponse>(pr => this.OnPublishResponse(pr), new ExecutionDataflowBlockOptions { SingleProducerConstrained = true });
            }

            // read [Subscription] attribute.
            var typeInfo = target.GetType().GetTypeInfo();
            var sa = typeInfo.GetCustomAttribute<SubscriptionAttribute>();
            if (sa != null)
            {
                this.EndpointUrl = sa.EndpointUrl;
                this.PublishingInterval = sa.PublishingInterval;
                this.KeepAliveCount = sa.KeepAliveCount;
                this.LifetimeCount = sa.LifetimeCount;
            }

            // read [MonitoredItem] attributes.
            foreach (var propertyInfo in typeInfo.DeclaredProperties)
            {
                var mia = propertyInfo.GetCustomAttribute<MonitoredItemAttribute>();
                if (mia == null || string.IsNullOrEmpty(mia.NodeId))
                {
                    continue;
                }

                MonitoringFilter filter = null;
                if (mia.AttributeId == AttributeIds.Value && (mia.DataChangeTrigger != DataChangeTrigger.StatusValue || mia.DeadbandType != DeadbandType.None))
                {
                    filter = new DataChangeFilter() { Trigger = mia.DataChangeTrigger, DeadbandType = (uint)mia.DeadbandType, DeadbandValue = mia.DeadbandValue };
                }

                var propType = propertyInfo.PropertyType;
                if (propType == typeof(DataValue))
                {
                    this.MonitoredItems.Add(new DataValueMonitoredItem(
                        property: propertyInfo,
                        nodeId: ExpandedNodeId.Parse(mia.NodeId),
                        indexRange: mia.IndexRange,
                        attributeId: mia.AttributeId,
                        samplingInterval: mia.SamplingInterval,
                        filter: filter,
                        queueSize: mia.QueueSize,
                        discardOldest: mia.DiscardOldest));
                    continue;
                }

                if (propType == typeof(BaseEvent) || propType.GetTypeInfo().IsSubclassOf(typeof(BaseEvent)))
                {
                    this.MonitoredItems.Add(new EventMonitoredItem(
                        property: propertyInfo,
                        nodeId: ExpandedNodeId.Parse(mia.NodeId),
                        indexRange: mia.IndexRange,
                        attributeId: mia.AttributeId,
                        samplingInterval: mia.SamplingInterval,
                        filter: new EventFilter() { SelectClauses = EventHelper.GetSelectClauses(propType) },
                        queueSize: mia.QueueSize,
                        discardOldest: mia.DiscardOldest));
                    continue;
                }

                if (propType == typeof(ObservableQueue<DataValue>))
                {
                    this.MonitoredItems.Add(new DataValueQueueMonitoredItem(
                        property: propertyInfo,
                        nodeId: ExpandedNodeId.Parse(mia.NodeId),
                        indexRange: mia.IndexRange,
                        attributeId: mia.AttributeId,
                        samplingInterval: mia.SamplingInterval,
                        filter: filter,
                        queueSize: mia.QueueSize,
                        discardOldest: mia.DiscardOldest));
                    continue;
                }

                if (propType.IsConstructedGenericType && propType.GetGenericTypeDefinition() == typeof(ObservableQueue<>))
                {
                    var elemType = propType.GenericTypeArguments[0];
                    if (elemType == typeof(BaseEvent) || elemType.GetTypeInfo().IsSubclassOf(typeof(BaseEvent)))
                    {
                        this.MonitoredItems.Add((MonitoredItemBase)Activator.CreateInstance(
                        typeof(EventQueueMonitoredItem<>).MakeGenericType(elemType),
                        propertyInfo,
                        ExpandedNodeId.Parse(mia.NodeId),
                        mia.AttributeId,
                        mia.IndexRange,
                        MonitoringMode.Reporting,
                        mia.SamplingInterval,
                        new EventFilter() { SelectClauses = EventHelper.GetSelectClauses(elemType) },
                        mia.QueueSize,
                        mia.DiscardOldest));
                        continue;
                    }
                }

                this.MonitoredItems.Add(new ValueMonitoredItem(
                    property: propertyInfo,
                    nodeId: ExpandedNodeId.Parse(mia.NodeId),
                    indexRange: mia.IndexRange,
                    attributeId: mia.AttributeId,
                    samplingInterval: mia.SamplingInterval,
                    filter: filter,
                    queueSize: mia.QueueSize,
                    discardOldest: mia.DiscardOldest));
            }

            // register for property change.
            var inpc = target as INotifyPropertyChanged;
            if (inpc != null)
            {
                inpc.PropertyChanged += this.OnPropertyChanged;
            }

            // store this in the shared attached subscriptions list
            attachedSubscriptions.Remove(target);
            attachedSubscriptions.Add(target, this);

            this.stateMachineCts = new CancellationTokenSource();
            this.stateMachineTask = Task.Run(() => this.StateMachineAsync(this.stateMachineCts.Token));

        }

        /// <summary>
        /// Gets the endpoint url.
        /// </summary>
        public string EndpointUrl { get; }

        /// <summary>
        /// Gets the publishing interval.
        /// </summary>
        public double PublishingInterval { get; } = UaTcpSessionChannel.DefaultPublishingInterval;

        /// <summary>
        /// Gets the number of PublishingIntervals before the server should return an empty Publish response.
        /// </summary>
        public uint KeepAliveCount { get; } = UaTcpSessionChannel.DefaultKeepaliveCount;

        /// <summary>
        /// Gets the number of PublishingIntervals before the server should delete the subscription.
        /// </summary>
        public uint LifetimeCount { get; } = 0u;

        /// <summary>
        /// Gets the collection of items to monitor.
        /// </summary>
        public MonitoredItemCollection MonitoredItems { get; } = new MonitoredItemCollection();

        /// <summary>
        /// Gets the application.
        /// </summary>
        public UaApplication Application => this.application;

        /// <summary>
        /// Gets the target.
        /// </summary>
        public object Target => this.subscriptionRef.Target;

        /// <summary>
        /// Gets the SubscriptionId assigned by the server.
        /// </summary>
        public uint SubscriptionId { get; internal set; }

        /// <summary>
        /// Gets the <see cref="CommunicationState"/>.
        /// </summary>
        public CommunicationState State { get; private set; }

        /// <summary>
        /// Gets the inner channel.
        /// </summary>
        protected UaTcpSessionChannel InnerChannel
        {
            get
            {
                if (this.innerChannel == null)
                {
                    throw new ServiceResultException(StatusCodes.BadServerNotConnected);
                }

                return this.innerChannel;
            }
        }

        /// <summary>
        /// Gets the current logger
        /// </summary>
        protected virtual ILogger Logger => this.logger;

        /// <summary>
        /// Gets the <see cref="Subscription"/> attached to this target object.
        /// </summary>
        /// <param name="target">the target.</param>
        /// <returns>Returns the attached <see cref="Subscription"/> or null.</returns>
        public static Subscription From(object target)
        {
            if (attachedSubscriptions.TryGetValue(target, out Subscription subscription))
            {
                return subscription;
            }

            return null;
        }

        /// <summary>
        /// Disposes the subscription.
        /// </summary>
        public void Dispose()
        {
            this.Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                this.stateMachineCts.Cancel();
                var target = this.Target;
                if (target != null)
                {
                    attachedSubscriptions.Remove(target);
                    var inpc = this.Target as INotifyPropertyChanged;
                    if (inpc != null)
                    {
                        inpc.PropertyChanged -= this.OnPropertyChanged;
                    }
                }
            }
        }

        /// <summary>
        /// Handles PublishResponse message.
        /// </summary>
        /// <param name="response">The publish response.</param>
        /// <returns>False if target reference is not alive.</returns>
        internal bool OnPublishResponse(PublishResponse response)
        {
            var target = this.Target;
            if (target == null)
            {
                return false;
            }

            this.isPublishing = true;
            try
            {
                // loop thru all the notifications
                var nd = response.NotificationMessage?.NotificationData;
                if (nd == null)
                {
                    return true;
                }

                foreach (var n in nd)
                {
                    // if data change.
                    var dcn = n as DataChangeNotification;
                    if (dcn != null)
                    {
                        MonitoredItemBase item;
                        foreach (var min in dcn.MonitoredItems)
                        {
                            if (this.MonitoredItems.TryGetValueByClientId(min.ClientHandle, out item))
                            {
                                try
                                {
                                    item.Publish(target, min.Value);
                                }
                                catch (Exception ex)
                                {
                                    this.Logger?.LogError($"Error publishing value for NodeId {item.NodeId}. {ex.Message}");
                                }
                            }
                        }

                        continue;
                    }

                    // if event.
                    var enl = n as EventNotificationList;
                    if (enl != null)
                    {
                        MonitoredItemBase item;
                        foreach (var efl in enl.Events)
                        {
                            if (this.MonitoredItems.TryGetValueByClientId(efl.ClientHandle, out item))
                            {
                                try
                                {
                                    item.Publish(target, efl.EventFields);
                                }
                                catch (Exception ex)
                                {
                                    this.Logger?.LogError($"Error publishing event for NodeId {item.NodeId}. {ex.Message}");
                                }
                            }
                        }
                    }
                }

                return true;
            }
            finally
            {
                this.isPublishing = false;
            }
        }

        /// <summary>
        /// Handles PropertyChanged event. If the property is associated with a MonitoredItem, writes the property value to the node of the server.
        /// </summary>
        /// <param name="sender">the sender.</param>
        /// <param name="e">the event.</param>
        internal async void OnPropertyChanged(object sender, PropertyChangedEventArgs e)
        {
            if (this.isPublishing || string.IsNullOrEmpty(e.PropertyName))
            {
                return;
            }

            MonitoredItemBase item;
            if (this.MonitoredItems.TryGetValueByName(e.PropertyName, out item))
            {
                DataValue value;
                if (item.TryGetValue(sender, out value))
                {
                    StatusCode statusCode;
                    try
                    {
                        var cts = new CancellationTokenSource((int)UaTcpSecureChannel.DefaultTimeoutHint);
                        var ch = await this.application.GetChannelAsync(this.EndpointUrl, cts.Token).ConfigureAwait(false);
                        var writeRequest = new WriteRequest
                        {
                            NodesToWrite = new[] { new WriteValue { NodeId = ExpandedNodeId.ToNodeId(item.NodeId, ch.NamespaceUris), AttributeId = item.AttributeId, IndexRange = item.IndexRange, Value = value } }
                        };
                        var writeResponse = await ch.WriteAsync(writeRequest).ConfigureAwait(false);
                        statusCode = writeResponse.Results[0];
                    }
                    catch (ServiceResultException ex)
                    {
                        statusCode = ex.StatusCode;
                    }
                    catch (Exception)
                    {
                        statusCode = StatusCodes.BadServerNotConnected;
                    }

                    item.OnWriteResult(sender, statusCode);
                    if (StatusCode.IsBad(statusCode))
                    {
                        this.Logger?.LogError($"Error writing value for {item.NodeId}. {StatusCodes.GetDefaultMessage(statusCode)}");
                    }
                }
            }
        }

        /// <summary>
        /// Signals the channel state is Closing.
        /// </summary>
        /// <param name="channel">The session channel. </param>
        /// <param name="token">A cancellation token. </param>
        /// <returns>A task.</returns>
        private static async Task WhenChannelClosingAsync(UaTcpSessionChannel channel, CancellationToken token = default(CancellationToken))
        {
            var tcs = new TaskCompletionSource<bool>();
            EventHandler handler = (o, e) => tcs.TrySetResult(true);
            using (token.Register(() => tcs.TrySetCanceled(), false))
            {
                try
                {
                    channel.Closing += handler;
                    if (channel.State == CommunicationState.Opened)
                    {
                        await tcs.Task;
                    }
                }
                finally
                {
                    channel.Closing -= handler;
                }
            }
        }

        /// <summary>
        /// The state machine manages the state of the subscription.
        /// </summary>
        /// <param name="token">A cancellation token.</param>
        /// <returns>A task.</returns>
        private async Task StateMachineAsync(CancellationToken token = default(CancellationToken))
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    //await this.whenSubscribed.Task.WithCancellation(token);
                    this.progress.Report(CommunicationState.Opening);

                    try
                    {
                        // get a channel.
                        this.innerChannel = await this.application.GetChannelAsync(this.EndpointUrl, token);

                        try
                        {
                            // create the subscription.
                            var subscriptionRequest = new CreateSubscriptionRequest
                            {
                                RequestedPublishingInterval = this.PublishingInterval,
                                RequestedMaxKeepAliveCount = this.KeepAliveCount,
                                RequestedLifetimeCount = Math.Max(this.LifetimeCount, 3 * this.KeepAliveCount),
                                PublishingEnabled = true
                            };
                            var subscriptionResponse = await this.innerChannel.CreateSubscriptionAsync(subscriptionRequest).ConfigureAwait(false);

                            // link up the dataflow blocks
                            var id = this.subscriptionId = subscriptionResponse.SubscriptionId;
                            var linkToken = this.innerChannel.LinkTo(this.actionBlock, pr => pr.SubscriptionId == id);

                            try
                            {
                                // create the monitored items.
                                var items = this.MonitoredItems.ToList();
                                if (items.Count > 0)
                                {
                                    var requests = items.Select(m => new MonitoredItemCreateRequest { ItemToMonitor = new ReadValueId { NodeId = ExpandedNodeId.ToNodeId(m.NodeId, this.InnerChannel.NamespaceUris), AttributeId = m.AttributeId, IndexRange = m.IndexRange }, MonitoringMode = m.MonitoringMode, RequestedParameters = new MonitoringParameters { ClientHandle = m.ClientId, DiscardOldest = m.DiscardOldest, QueueSize = m.QueueSize, SamplingInterval = m.SamplingInterval, Filter = m.Filter } }).ToArray();
                                    var itemsRequest = new CreateMonitoredItemsRequest
                                    {
                                        SubscriptionId = id,
                                        ItemsToCreate = requests,
                                    };
                                    var itemsResponse = await this.innerChannel.CreateMonitoredItemsAsync(itemsRequest);
                                    for (int i = 0; i < itemsResponse.Results.Length; i++)
                                    {
                                        var item = items[i];
                                        var result = itemsResponse.Results[i];
                                        item.OnCreateResult(this, result);
                                        if (StatusCode.IsBad(result.StatusCode))
                                        {
                                            this.logger?.LogError($"Error creating MonitoredItem for {item.NodeId}. {StatusCodes.GetDefaultMessage(result.StatusCode)}");
                                        }
                                    }
                                }

                                this.progress.Report(CommunicationState.Opened);

                                // wait here until channel is closing, unsubscribed or token cancelled.
                                try
                                {
                                    await WhenChannelClosingAsync(this.innerChannel, token);
                                    //using (var cts = CancellationTokenSource.CreateLinkedTokenSource(token))
                                    //{

                                    //    await Task.WhenAny(
                                    //        WhenChannelClosingAsync(this.innerChannel, cts.Token),
                                    //        this.whenUnsubscribed.Task);
                                    //    cts.Cancel();
                                    //}
                                }
                                catch (OperationCanceledException)
                                {
                                }
                                finally
                                {
                                    this.progress.Report(CommunicationState.Closing);
                                }
                            }
                            catch (Exception ex)
                            {
                                this.logger?.LogError($"Error creating MonitoredItems. {ex.Message}");
                                this.progress.Report(CommunicationState.Faulted);
                            }
                            finally
                            {
                                linkToken.Dispose();
                            }

                            if (this.innerChannel.State == CommunicationState.Opened)
                            {
                                try
                                {
                                    // delete the subscription.
                                    var deleteRequest = new DeleteSubscriptionsRequest
                                    {
                                        SubscriptionIds = new uint[] { id }
                                    };
                                    await this.innerChannel.DeleteSubscriptionsAsync(deleteRequest);
                                }
                                catch (Exception ex)
                                {
                                    this.logger?.LogError($"Error deleting subscription. {ex.Message}");
                                    await Task.Delay(2000);
                                }
                            }

                            this.progress.Report(CommunicationState.Closed);
                            this.innerChannel = null;
                        }
                        catch (Exception ex)
                        {
                            this.logger?.LogError($"Error creating subscription. {ex.Message}");
                            this.progress.Report(CommunicationState.Faulted);
                            this.innerChannel = null;
                            await Task.Delay(2000);
                        }
                    }
                    catch (Exception ex)
                    {
                        this.logger?.LogError($"Error getting channel. {ex.Message}");
                        this.progress.Report(CommunicationState.Faulted);
                        await Task.Delay(2000);
                    }
                }
                catch (OperationCanceledException)
                {
                }
            }
        }
    }
}