// Copyright (c) Converter Systems LLC. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Reactive.Linq;
using System.Reflection;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Workstation.Collections;
using Workstation.ServiceModel.Ua;
using Workstation.ServiceModel.Ua.Channels;
using System.Threading;

namespace Workstation.UaClient.UnitTests
{
    [TestClass]
    public class UnitTest1
    {
        // private const string EndpointUrl = "opc.tcp://localhost:16664"; // open62541
        // private const string EndpointUrl = "opc.tcp://bculz-PC:53530/OPCUA/SimulationServer"; // the endpoint of the Prosys UA Simulation Server
        // private const string EndpointUrl = "opc.tcp://localhost:51210/UA/SampleServer"; // the endpoint of the OPCF SampleServer
        private const string EndpointUrl = "opc.tcp://localhost:48010"; // the endpoint of the UaCPPServer.
        // private const string EndpointUrl = "opc.tcp://localhost:26543"; // the endpoint of the Workstation.RobotServer.
        //private const string EndpointUrl = "opc.tcp://192.168.0.11:4840"; // the endpoint of the Siemens 1500 PLC.

        private readonly ILoggerFactory loggerFactory;
        private readonly ILogger<UnitTest1> logger;
        private readonly ApplicationDescription localDescription;
        private readonly ICertificateStore certificateStore;

        public UnitTest1()
        {
            this.loggerFactory = new LoggerFactory();
            this.loggerFactory.AddDebug(LogLevel.Trace);
            this.logger = this.loggerFactory?.CreateLogger<UnitTest1>();

            this.localDescription = new ApplicationDescription
            {
                ApplicationName = "Workstation.UaClient.UnitTests",
                ApplicationUri = $"urn:{Dns.GetHostName()}:Workstation.UaClient.UnitTests",
                ApplicationType = ApplicationType.Client
            };

            this.certificateStore = new DirectoryStore(
                Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Workstation.UaClient.UnitTests",
                    "pki"));
        }

        /// <summary>
        /// Tests endpoint with no security and with no Certificate.
        /// </summary>
        /// <returns>A <see cref="Task"/> representing the asynchronous unit test.</returns>
        [TestMethod]
        public async Task ConnnectToEndpointsWithNoSecurityAndWithNoCertificate()
        {
            // discover available endpoints of server.
            var getEndpointsRequest = new GetEndpointsRequest
            {
                EndpointUrl = EndpointUrl,
                ProfileUris = new[] { TransportProfileUris.UaTcpTransport }
            };
            Console.WriteLine($"Discovering endpoints of '{getEndpointsRequest.EndpointUrl}'.");
            var getEndpointsResponse = await UaTcpDiscoveryService.GetEndpointsAsync(getEndpointsRequest, this.loggerFactory);

            // for each endpoint and user identity type, try creating a session and reading a few nodes.
            foreach (var selectedEndpoint in getEndpointsResponse.Endpoints.Where(e => e.SecurityPolicyUri == SecurityPolicyUris.None))
            {
                foreach (var selectedTokenPolicy in selectedEndpoint.UserIdentityTokens)
                {
                    IUserIdentity selectedUserIdentity;
                    switch (selectedTokenPolicy.TokenType)
                    {
                        case UserTokenType.UserName:
                            selectedUserIdentity = new UserNameIdentity("root", "secret");
                            break;

                        case UserTokenType.Anonymous:
                            selectedUserIdentity = new AnonymousIdentity();
                            break;

                        default:
                            continue;
                    }

                    var channel = new UaTcpSessionChannel(
                        this.localDescription,
                        null,
                        selectedUserIdentity,
                        selectedEndpoint,
                        loggerFactory: this.loggerFactory);

                    await channel.OpenAsync();
                    Console.WriteLine($"Opened session with endpoint '{channel.RemoteEndpoint.EndpointUrl}'.");
                    Console.WriteLine($"SecurityPolicy: '{channel.RemoteEndpoint.SecurityPolicyUri}'.");
                    Console.WriteLine($"SecurityMode: '{channel.RemoteEndpoint.SecurityMode}'.");
                    Console.WriteLine($"UserIdentityToken: '{channel.UserIdentity}'.");

                    Console.WriteLine($"Closing session '{channel.SessionId}'.");
                    await channel.CloseAsync();
                }
            }
        }

        /// <summary>
        /// Tests all combinations of endpoint security and user identity types supported by the server.
        /// </summary>
        /// <returns>A <see cref="Task"/> representing the asynchronous unit test.</returns>
        [TestMethod]
        public async Task ConnnectToAllEndpoints()
        {
            // discover available endpoints of server.
            var getEndpointsRequest = new GetEndpointsRequest
            {
                EndpointUrl = EndpointUrl,
                ProfileUris = new[] { TransportProfileUris.UaTcpTransport }
            };
            Console.WriteLine($"Discovering endpoints of '{getEndpointsRequest.EndpointUrl}'.");
            var getEndpointsResponse = await UaTcpDiscoveryService.GetEndpointsAsync(getEndpointsRequest);

            // for each endpoint and user identity type, try creating a session and reading a few nodes.
            foreach (var selectedEndpoint in getEndpointsResponse.Endpoints.OrderBy(e => e.SecurityLevel))
            {
                foreach (var selectedTokenPolicy in selectedEndpoint.UserIdentityTokens)
                {
                    IUserIdentity selectedUserIdentity;
                    switch (selectedTokenPolicy.TokenType)
                    {
                        case UserTokenType.UserName:
                            selectedUserIdentity = new UserNameIdentity("root", "secret");
                            break;

                        case UserTokenType.Anonymous:
                            selectedUserIdentity = new AnonymousIdentity();
                            break;

                        default:
                            continue;
                    }

                    var channel = new UaTcpSessionChannel(
                        this.localDescription,
                        this.certificateStore,
                        selectedUserIdentity,
                        selectedEndpoint,
                        loggerFactory: this.loggerFactory);

                    await channel.OpenAsync();
                    Console.WriteLine($"Opened session with endpoint '{channel.RemoteEndpoint.EndpointUrl}'.");
                    Console.WriteLine($"SecurityPolicy: '{channel.RemoteEndpoint.SecurityPolicyUri}'.");
                    Console.WriteLine($"SecurityMode: '{channel.RemoteEndpoint.SecurityMode}'.");
                    Console.WriteLine($"UserIdentityToken: '{channel.UserIdentity}'.");

                    Console.WriteLine($"Closing session '{channel.SessionId}'.");
                    await channel.CloseAsync();
                }
            }
        }

        /// <summary>
        /// Tests result of session timeout causes server to close socket.
        /// </summary>
        /// <returns>A <see cref="Task"/> representing the asynchronous unit test.</returns>
        [TestMethod]
        [ExpectedException(typeof(ServiceResultException), "The session id is not valid.")]
        public async Task SessionTimeoutCausesFault()
        {
            var channel = new UaTcpSessionChannel(
                this.localDescription,
                this.certificateStore,
                new AnonymousIdentity(),
                EndpointUrl,
                loggerFactory: this.loggerFactory,
                options: new UaTcpSessionChannelOptions { SessionTimeout = 10000 });

            await channel.OpenAsync();
            Console.WriteLine($"Opened session with endpoint '{channel.RemoteEndpoint.EndpointUrl}'.");
            Console.WriteLine($"SecurityPolicy: '{channel.RemoteEndpoint.SecurityPolicyUri}'.");
            Console.WriteLine($"SecurityMode: '{channel.RemoteEndpoint.SecurityMode}'.");
            Console.WriteLine($"Activated session '{channel.SessionId}'.");

            // server should close session due to inactivity
            await Task.Delay(20000);

            // should throw exception
            var readRequest = new ReadRequest { NodesToRead = new[] { new ReadValueId { NodeId = NodeId.Parse(VariableIds.Server_ServerStatus_CurrentTime), AttributeId = AttributeIds.Value } } };
            await channel.ReadAsync(readRequest);

            Console.WriteLine($"Closing session '{channel.SessionId}'.");
            await channel.CloseAsync();
        }

        [TestMethod]
        public async Task ReadHistorical()
        {
            var channel = new UaTcpSessionChannel(
                this.localDescription,
                this.certificateStore,
                new AnonymousIdentity(),
                EndpointUrl,
                loggerFactory: this.loggerFactory);

            await channel.OpenAsync();
            Console.WriteLine($"Opened session with endpoint '{channel.RemoteEndpoint.EndpointUrl}'.");
            Console.WriteLine($"SecurityPolicy: '{channel.RemoteEndpoint.SecurityPolicyUri}'.");
            Console.WriteLine($"SecurityMode: '{channel.RemoteEndpoint.SecurityMode}'.");
            Console.WriteLine($"Activated session '{channel.SessionId}'.");

            var historyReadRequest = new HistoryReadRequest
            {
                HistoryReadDetails = new ReadRawModifiedDetails
                {
                    StartTime = DateTime.UtcNow - TimeSpan.FromMinutes(10),
                    EndTime = DateTime.UtcNow,
                    ReturnBounds = true,
                    IsReadModified = false
                },
                NodesToRead = new[]
                {
                    new HistoryReadValueId
                    {
                        NodeId = NodeId.Parse("ns=2;s=Demo.History.DoubleWithHistory")
                    }
                },
            };
            var historyReadResponse = await channel.HistoryReadAsync(historyReadRequest);
            var result = historyReadResponse.Results[0];
            Assert.IsTrue(StatusCode.IsGood(result.StatusCode));
            Console.WriteLine($"HistoryRead response status code: {result.StatusCode}, HistoryData count: {((HistoryData)result.HistoryData).DataValues.Length}.");

            var historyReadRequest2 = new HistoryReadRequest
            {
                HistoryReadDetails = new ReadEventDetails
                {
                    StartTime = DateTime.UtcNow - TimeSpan.FromMinutes(10),
                    EndTime = DateTime.UtcNow,
                    Filter = new EventFilter // Use EventHelper to select all the fields of AlarmCondition.
                    {
                        SelectClauses = EventHelper.GetSelectClauses<AlarmCondition>()
                    }
                },
                NodesToRead = new[]
                {
                    new HistoryReadValueId
                    {
                        NodeId = NodeId.Parse("ns=2;s=Demo.History.DoubleWithHistory")
                    }
                },
            };
            var historyReadResponse2 = await channel.HistoryReadAsync(historyReadRequest2);
            var result2 = historyReadResponse2.Results[0];
            Assert.IsTrue(StatusCode.IsGood(result2.StatusCode));
            Console.WriteLine($"HistoryRead response status code: {result2.StatusCode}, HistoryEvent count: {((HistoryEvent)result2.HistoryData).Events.Length}.");

            // Use EventHelper to create AlarmConditions from the HistoryEventFieldList
            var alarms = ((HistoryEvent)result2.HistoryData).Events.Select(e => EventHelper.Deserialize<AlarmCondition>(e.EventFields));

            Console.WriteLine($"Closing session '{channel.SessionId}'.");
            await channel.CloseAsync();
        }

        /// <summary>
        /// Tests connecting to endpoint and creating subscriptions.
        /// </summary>
        /// <returns>A <see cref="Task"/> representing the asynchronous unit test.</returns>
        [TestMethod]
        public async Task TestSubscription()
        {
            // Read 'appSettings.json' for endpoint configuration
            var config = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appSettings.json", true)
                .Build();

            var app = new UaApplicationBuilder()
                .SetApplicationUri($"urn:{Dns.GetHostName()}:Workstation.UaClient.UnitTests")
                .SetDirectoryStore(Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Workstation.UaClient.UnitTests",
                    "pki"))
                //.SetIdentity(new UserNameIdentity("root", "secret"))
                //.AddMappedEndpoints(config)
                .SetLoggerFactory(this.loggerFactory)
                .ConfigureOptions(o => o.SessionTimeout = 30000)
            // .ConfigureChannel(c => c.)
                .Build();
            app.Run();

            var sub = new MySubscription();

            //var tok = app.Subscribe(sub);
            //var d = new PropertyChangedEventHandler((s, e) => { });
            //sub.PropertyChanged += d;

            Console.WriteLine($"Created subscription.");

            await Task.Delay(5000);

            //sub.PropertyChanged -= d;
            //tok.Dispose();
            var dateTime = sub.CurrentTime;
            var dataValue = sub.CurrentTimeAsDataValue;
            var queueCount = sub.CurrentTimeQueue.Count;
            sub = null;
            GC.Collect();
            await Task.Delay(5000);

            app.Dispose();

            Assert.IsTrue(dateTime != DateTime.MinValue, "CurrentTime");
            Assert.IsTrue(dataValue != null, "CurrentTimeAsDataValue");
            Assert.IsTrue(queueCount > 0, "CurrentTimeQueue");
        }

        [Subscription(endpointUrl: EndpointUrl, publishingInterval: 500, keepAliveCount: 20)]
        private class MySubscription : SubscriptionBase
        {
            /// <summary>
            /// Gets the value of CurrentTime.
            /// </summary>
            [MonitoredItem(nodeId: "i=2258")]
            public DateTime CurrentTime
            {
                get { return this.currentTime; }
                private set { this.currentTime = value; }
            }

            private DateTime currentTime;

            /// <summary>
            /// Gets the value of CurrentTimeAsDataValue.
            /// </summary>
            [MonitoredItem(nodeId: "i=2258")]
            public DataValue CurrentTimeAsDataValue
            {
                get { return this.currentTimeAsDataValue; }
                private set { this.currentTimeAsDataValue = value; }
            }

            private DataValue currentTimeAsDataValue;

            /// <summary>
            /// Gets the value of CurrentTimeQueue.
            /// </summary>
            [MonitoredItem(nodeId: "i=2258")]
            public ObservableQueue<DataValue> CurrentTimeQueue { get; } = new ObservableQueue<DataValue>(capacity: 16, isFixedSize: true);
        }

        [TestMethod]
        public async Task StackTest()
        {
            var channel = new UaTcpSessionChannel(
                this.localDescription,
                this.certificateStore,
                new AnonymousIdentity(),
                EndpointUrl,
                loggerFactory: this.loggerFactory);

            await channel.OpenAsync();
            Console.WriteLine($"Opened session with endpoint '{channel.RemoteEndpoint.EndpointUrl}'.");
            Console.WriteLine($"SecurityPolicy: '{channel.RemoteEndpoint.SecurityPolicyUri}'.");
            Console.WriteLine($"SecurityMode: '{channel.RemoteEndpoint.SecurityMode}'.");
            Console.WriteLine($"Activated session '{channel.SessionId}'.");

            var readRequest = new ReadRequest
            {
                NodesToRead = new[]
                {
                new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=2;s=Demo.Static.Scalar.Boolean") },
                new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=2;s=Demo.Static.Scalar.SByte") },
                new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=2;s=Demo.Static.Scalar.Int16") },
                new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=2;s=Demo.Static.Scalar.Int32") },
                new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=2;s=Demo.Static.Scalar.Int64") },
                new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=2;s=Demo.Static.Scalar.Byte") },
                new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=2;s=Demo.Static.Scalar.UInt16") },
                new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=2;s=Demo.Static.Scalar.UInt32") },
                new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=2;s=Demo.Static.Scalar.UInt64") },
                new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=2;s=Demo.Static.Scalar.Float") },
                new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=2;s=Demo.Static.Scalar.Double") },
                new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=2;s=Demo.Static.Scalar.String") },
                new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=2;s=Demo.Static.Scalar.DateTime") },
                new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=2;s=Demo.Static.Scalar.Guid") },
                new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=2;s=Demo.Static.Scalar.ByteString") },
                new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=2;s=Demo.Static.Scalar.XmlElement") },
                new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=2;s=Demo.Static.Scalar.LocalizedText") },
                new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=2;s=Demo.Static.Scalar.QualifiedName") },
                new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=2;s=Demo.Static.Arrays.Boolean") },
                new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=2;s=Demo.Static.Arrays.SByte") },
                new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=2;s=Demo.Static.Arrays.Int16") },
                new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=2;s=Demo.Static.Arrays.Int32") },
                new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=2;s=Demo.Static.Arrays.Int64") },
                new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=2;s=Demo.Static.Arrays.Byte") },
                new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=2;s=Demo.Static.Arrays.UInt16") },
                new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=2;s=Demo.Static.Arrays.UInt32") },
                new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=2;s=Demo.Static.Arrays.UInt64") },
                new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=2;s=Demo.Static.Arrays.Float") },
                new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=2;s=Demo.Static.Arrays.Double") },
                new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=2;s=Demo.Static.Arrays.String") },
                new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=2;s=Demo.Static.Arrays.DateTime") },
                new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=2;s=Demo.Static.Arrays.Guid") },
                new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=2;s=Demo.Static.Arrays.ByteString") },
                new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=2;s=Demo.Static.Arrays.XmlElement") },
                new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=2;s=Demo.Static.Arrays.LocalizedText") },
                new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=2;s=Demo.Static.Arrays.QualifiedName") },
                },
            };

            readRequest = new ReadRequest
            {
                NodesToRead = new[]
               {
                new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("i=11494") },
                },
            };
            var sw = new Stopwatch();
            sw.Restart();
            for (int i = 0; i < 1; i++)
            {
                var readResponse = await channel.ReadAsync(readRequest);
                foreach (var result in readResponse.Results)
                {
                    Assert.IsTrue(StatusCode.IsGood(result.StatusCode));
                    var obj = result.GetValue();
                }
            }

            sw.Stop();
            Console.WriteLine($"{sw.ElapsedMilliseconds} ms");

            Console.WriteLine($"Closing session '{channel.SessionId}'.");
            await channel.CloseAsync();
        }

        /// <summary>
        /// Tests result of transfer subscription from channel1 to channel2.
        /// </summary>
        /// <returns>A <see cref="Task"/> representing the asynchronous unit test.</returns>
        [TestMethod]
        public async Task TransferSubscription()
        {
            var channel1 = new UaTcpSessionChannel(
                this.localDescription,
                this.certificateStore,
                new UserNameIdentity("root", "secret"),
                EndpointUrl,
                loggerFactory: this.loggerFactory);

            await channel1.OpenAsync();
            Console.WriteLine($"Opened session with endpoint '{channel1.RemoteEndpoint.EndpointUrl}'.");
            Console.WriteLine($"SecurityPolicy: '{channel1.RemoteEndpoint.SecurityPolicyUri}'.");
            Console.WriteLine($"SecurityMode: '{channel1.RemoteEndpoint.SecurityMode}'.");
            Console.WriteLine($"Activated session '{channel1.SessionId}'.");

            // create the keep alive subscription.
            var subscriptionRequest = new CreateSubscriptionRequest
            {
                RequestedPublishingInterval = 1000f,
                RequestedMaxKeepAliveCount = 30,
                RequestedLifetimeCount = 30 * 3,
                PublishingEnabled = true,
            };
            var subscriptionResponse = await channel1.CreateSubscriptionAsync(subscriptionRequest).ConfigureAwait(false);
            var id = subscriptionResponse.SubscriptionId;

            var token = channel1.Where(pr => pr.SubscriptionId == id).Subscribe(pr =>
            {
                // loop thru all the data change notifications
                var dcns = pr.NotificationMessage.NotificationData.OfType<DataChangeNotification>();
                foreach (var dcn in dcns)
                {
                    foreach (var min in dcn.MonitoredItems)
                    {
                        Console.WriteLine($"channel: 1; sub: {pr.SubscriptionId}; handle: {min.ClientHandle}; value: {min.Value}");
                    }
                }
            });

            var itemsRequest = new CreateMonitoredItemsRequest
            {
                SubscriptionId = id,
                ItemsToCreate = new MonitoredItemCreateRequest[]
                {
                    new MonitoredItemCreateRequest { ItemToMonitor = new ReadValueId { NodeId = NodeId.Parse("i=2258"), AttributeId = AttributeIds.Value }, MonitoringMode = MonitoringMode.Reporting, RequestedParameters = new MonitoringParameters { ClientHandle = 12345, SamplingInterval = -1, QueueSize = 0, DiscardOldest = true } }
                },
            };
            var itemsResponse = await channel1.CreateMonitoredItemsAsync(itemsRequest);

            await Task.Delay(3000);

            var channel2 = new UaTcpSessionChannel(
                this.localDescription,
                this.certificateStore,
                new UserNameIdentity("root", "secret"),
                EndpointUrl);

            await channel2.OpenAsync();
            var token2 = channel2.Where(pr => pr.SubscriptionId == id).Subscribe(pr =>
            {
                // loop thru all the data change notifications
                var dcns = pr.NotificationMessage.NotificationData.OfType<DataChangeNotification>();
                foreach (var dcn in dcns)
                {
                    foreach (var min in dcn.MonitoredItems)
                    {
                        Console.WriteLine($"channel: 2; sub: {pr.SubscriptionId}; handle: {min.ClientHandle}; value: {min.Value}");
                    }
                }
            });

            var transferRequest = new TransferSubscriptionsRequest
            {
                SubscriptionIds = new[] { id },
                SendInitialValues = true
            };
            var transferResult = await channel2.TransferSubscriptionsAsync(transferRequest);

            Assert.IsTrue(StatusCode.IsGood(transferResult.Results[0].StatusCode));

            await Task.Delay(3000);

            Console.WriteLine($"Closing session '{channel1.SessionId}'.");
            await channel1.CloseAsync();

            Console.WriteLine($"Closing session '{channel2.SessionId}'.");
            await channel2.CloseAsync();
        }

        [TestMethod]
        public async Task BrowseRoot()
        {
            var channel = new UaTcpSessionChannel(
                this.localDescription,
                this.certificateStore,
                new AnonymousIdentity(),
                EndpointUrl,
                SecurityPolicyUris.None,
                loggerFactory: this.loggerFactory);

            await channel.OpenAsync();

            var rds = new List<ReferenceDescription>();
            var browseRequest = new BrowseRequest { NodesToBrowse = new[] { new BrowseDescription { NodeId = ExpandedNodeId.ToNodeId(ExpandedNodeId.Parse(ObjectIds.RootFolder), channel.NamespaceUris), ReferenceTypeId = NodeId.Parse(ReferenceTypeIds.HierarchicalReferences), ResultMask = (uint)BrowseResultMask.TargetInfo, NodeClassMask = (uint)NodeClass.Unspecified, BrowseDirection = BrowseDirection.Forward, IncludeSubtypes = true } }, RequestedMaxReferencesPerNode = 1000 };
            var browseResponse = await channel.BrowseAsync(browseRequest).ConfigureAwait(false);
            rds.AddRange(browseResponse.Results.Where(result => result.References != null).SelectMany(result => result.References));
            var continuationPoints = browseResponse.Results.Select(br => br.ContinuationPoint).Where(cp => cp != null).ToArray();
            while (continuationPoints.Length > 0)
            {
                var browseNextRequest = new BrowseNextRequest { ContinuationPoints = continuationPoints, ReleaseContinuationPoints = false };
                var browseNextResponse = await channel.BrowseNextAsync(browseNextRequest);
                rds.AddRange(browseNextResponse.Results.Where(result => result.References != null).SelectMany(result => result.References));
                continuationPoints = browseNextResponse.Results.Select(br => br.ContinuationPoint).Where(cp => cp != null).ToArray();
            }

            Assert.IsTrue(rds.Count == 3);

            Console.WriteLine($"Closing session '{channel.SessionId}'.");
            await channel.CloseAsync();
        }

        [TestMethod]
        public async Task VectorAdd()
        {
            var channel = new UaTcpSessionChannel(
                this.localDescription,
                this.certificateStore,
                new AnonymousIdentity(),
                "opc.tcp://localhost:48010",
                SecurityPolicyUris.None,
                loggerFactory: this.loggerFactory,
                additionalTypes: new[] { typeof(Vector) });

            await channel.OpenAsync();

            Console.WriteLine("4 - Call VectorAdd method with structure arguments.");
            var v1 = new Vector { X = 1.0, Y = 2.0, Z = 3.0 };
            var v2 = new Vector { X = 1.0, Y = 2.0, Z = 3.0 };
            var request = new CallRequest
            {
                MethodsToCall = new[] {
                    new CallMethodRequest
                    {
                        ObjectId = NodeId.Parse("ns=2;s=Demo.Method"),
                        MethodId = NodeId.Parse("ns=2;s=Demo.Method.VectorAdd"),
                        InputArguments = new [] { new Variant(v1), new Variant(v2) }
                    }
                }
            };
            var response = await channel.CallAsync(request);
            var result = response.Results[0].OutputArguments[0].GetValueOrDefault<Vector>();

            Console.WriteLine($"  {v1}");
            Console.WriteLine($"+ {v2}");
            Console.WriteLine(@"  ------------------");
            Console.WriteLine($"  {result}");

            Assert.IsTrue(result.Z == 6.0);

            Console.WriteLine($"Closing session '{channel.SessionId}'.");
            await channel.CloseAsync();
        }

        [DataTypeId("nsu=http://www.unifiedautomation.com/DemoServer/;i=3002")]
        [BinaryEncodingId("nsu=http://www.unifiedautomation.com/DemoServer/;i=5054")]
        public class Vector : Structure
        {
            public double X { get; set; }

            public double Y { get; set; }

            public double Z { get; set; }

            public override void Encode(IEncoder encoder)
            {
                encoder.WriteDouble("X", this.X);
                encoder.WriteDouble("Y", this.Y);
                encoder.WriteDouble("Z", this.Z);
            }

            public override void Decode(IDecoder decoder)
            {
                this.X = decoder.ReadDouble("X");
                this.Y = decoder.ReadDouble("Y");
                this.Z = decoder.ReadDouble("Z");
            }

            public override string ToString() => $"{{ X={this.X}; Y={this.Y}; Z={this.Z}; }}";
        }

        [TestMethod]
        public async Task Test1()
        {
            var cts = new CancellationTokenSource(2000);
            try
            {
                await Task.Delay(5000).ContinueWith(t => Console.WriteLine(t.Status), cts.Token);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }

        [TestMethod]
        public async Task StackTest2()
        {
            var channel = new UaTcpSessionChannel(
                this.localDescription,
                this.certificateStore,
                new AnonymousIdentity(),
                EndpointUrl,
                loggerFactory: this.loggerFactory);

            await channel.OpenAsync();
            Console.WriteLine($"Opened session with endpoint '{channel.RemoteEndpoint.EndpointUrl}'.");
            Console.WriteLine($"SecurityPolicy: '{channel.RemoteEndpoint.SecurityPolicyUri}'.");
            Console.WriteLine($"SecurityMode: '{channel.RemoteEndpoint.SecurityMode}'.");
            Console.WriteLine($"Activated session '{channel.SessionId}'.");

            var readRequest = new ReadRequest
            {
                NodesToRead = new[]
                {
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV137\".\"Output\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV137\".\"Automatic\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV137\".\"Fault\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV137\".\"Output0\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV111\".\"Output\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV111\".\"Automatic\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV111\".\"Fault\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV111\".\"Output0\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"YY105\".\"Output\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"ZIC690\".\"BlowCmd\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV132\".\"Output\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV132\".\"Automatic\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV132\".\"Fault\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV132\".\"Output0\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"ZIC690\".\"ChargeCmd\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"HS999\".\"Input\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"PAL140\".\"Output\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"PALL140\".\"Output\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV113\".\"Output\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV113\".\"Automatic\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV113\".\"Fault\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV113\".\"Output0\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"ZIC690\".\"StopCmd\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"YY900\".\"Output\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"ZIC690\".\"HeatCmd\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SY729\".\"Forward\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SY729\".\"Reverse\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FIC110\".\"Automatic\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV112\".\"Output\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV112\".\"Automatic\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV112\".\"Fault\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV112\".\"Fault\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FIC110\".\"Cascade\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV112\".\"Output0\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"PAL110\".\"Output\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"ZIC690\".\"JogFwdCmd\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"ZIC690\".\"JogRevCmd\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SY718\".\"Forward\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SY718\".\"Reverse\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"ZIC680\".\"StopCmd\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"ZIC680\".\"BlowCmd\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"ZIC680\".\"RetractCmd\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue1\".\"Run\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue2\".\"Run\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FRC120\".\"Cascade\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV121\".\"Output\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV121\".\"Automatic\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV121\".\"Fault\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV121\".\"Output0\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FIC100\".\"Automatic\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV102\".\"Output\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV102\".\"Automatic\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV102\".\"Fault\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV102\".\"Fault\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FIC100\".\"Cascade\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV102\".\"Output0\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"PAL100\".\"Output\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV101\".\"Output\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV101\".\"Automatic\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV101\".\"Fault\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV101\".\"Output0\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SY727\".\"Forward\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SY727\".\"Reverse\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV118\".\"Output\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV118\".\"Automatic\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV118\".\"Fault\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV118\".\"Output0\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"HS000\".\"Input\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"ZIC690\".\"SampleCmd\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"PIC115\".\"Automatic\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"PIC115\".\"Cascade\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"PAL145\".\"Output\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"PALL145\".\"Output\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV117\".\"Output\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV117\".\"Automatic\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV117\".\"Fault\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV117\".\"Output0\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"HS100\".\"Input\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"Tapped\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FIC150\".\"Automatic\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV152\".\"Output\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV152\".\"Automatic\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV152\".\"Fault\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FIC150\".\"Cascade\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV152\".\"Output0\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"AC000\".\"SampleOnActionComplete\"") },


 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"AC000\".\"ActionSel\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"Balance\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"LiningHeats\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"In\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Out\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue1\".\"In\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue1\".\"Out\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue2\".\"In\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue2\".\"Out\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"OrderedMaterials\".\"In\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"OrderedMaterials\".\"Out\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"HS103\".\"Output\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"HS102\".\"Input\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Shell\".\"AvgHeatsInCampaign\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"In\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SY800\".\"ForwardInterlock\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SY800\".\"ReverseInterlock\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SY811\".\"ForwardInterlock\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SY811\".\"ReverseInterlock\"") },


 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FQ110\".\"Output\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"BathO2Total\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Practice\".\"Beta\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"COFlow\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"ZT690\".\"Output\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"ZIC690\".\"PosDevSlow\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"ZIC690\".\"PosDevStop\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"ZIC690\".\"PosSpBlow\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"ZS698\".\"Setpoint\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"ZS697\".\"Setpoint\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"ZIC690\".\"PosSpCharge\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"ZS694\".\"Setpoint\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"ZIC690\".\"PosSpHeat\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"ZS693\".\"Setpoint\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"ZIC690\".\"PosSpSample\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"ZS696\".\"Setpoint\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"CRE\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"PT140\".\"Output\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Practice\".\"CT_SP_STIR\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"PIC140\".\"DerivativeTime\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"PIC140\".\"IntegralTime\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"DecarbRate\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"AC000\".\"DecPctC\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"AC000\".\"DecTempMin\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"AC000\".\"FuelO2Preset\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"AC000\".\"FuelO2Total\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"AC000\".\"FuelTempBath\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV100\".\"Output\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV110\".\"Output\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV115\".\"Output\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FV150\".\"Output\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Practice\".\"HeatLossFactor\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FIC110\".\"Output\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FIC110\".\"Gain\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"PT110\".\"Output\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FIC110\".\"Input\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FIC110\".\"Setpoint\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Practice\".\"IN_SP_FUEL\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Practice\".\"IN_SP_MAX\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Practice\".\"IN_SP_MIN\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Practice\".\"IN_SP_RED\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Practice\".\"IN_SP_STIR\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"PIC140\".\"StandbyOutput\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FIC110\".\"DerivativeTime\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"TT110\".\"Output\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FIC110\".\"IntegralTime\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"ZT680\".\"Output\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"ZIC680\".\"PosDevSlow\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"ZIC680\".\"PosDevStop\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"ZIC680\".\"PosSpBlow\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"ZIC680\".\"SpeedSpFastFwd\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"ZIC680\".\"SpeedSpFastRev\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"ZIC680\".\"SpeedSpSlowFwd\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"ZIC680\".\"SpeedSpSlowRev\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[0].\"Metal\".\"Component\".\"Al\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[1].\"Metal\".\"Component\".\"Al\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[2].\"Metal\".\"Component\".\"Al\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[3].\"Metal\".\"Component\".\"Al\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[4].\"Metal\".\"Component\".\"Al\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[5].\"Metal\".\"Component\".\"Al\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[6].\"Metal\".\"Component\".\"Al\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[7].\"Metal\".\"Component\".\"Al\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[8].\"Metal\".\"Component\".\"Al\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[9].\"Metal\".\"Component\".\"Al\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[10].\"Metal\".\"Component\".\"Al\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[11].\"Metal\".\"Component\".\"Al\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[12].\"Metal\".\"Component\".\"Al\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[13].\"Metal\".\"Component\".\"Al\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[14].\"Metal\".\"Component\".\"Al\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[15].\"Metal\".\"Component\".\"Al\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[0].\"Slag\".\"Component\".\"Al2O3\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[1].\"Slag\".\"Component\".\"Al2O3\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[2].\"Slag\".\"Component\".\"Al2O3\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[3].\"Slag\".\"Component\".\"Al2O3\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[4].\"Slag\".\"Component\".\"Al2O3\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[5].\"Slag\".\"Component\".\"Al2O3\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[6].\"Slag\".\"Component\".\"Al2O3\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[7].\"Slag\".\"Component\".\"Al2O3\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[8].\"Slag\".\"Component\".\"Al2O3\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[9].\"Slag\".\"Component\".\"Al2O3\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[10].\"Slag\".\"Component\".\"Al2O3\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[11].\"Slag\".\"Component\".\"Al2O3\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[12].\"Slag\".\"Component\".\"Al2O3\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[13].\"Slag\".\"Component\".\"Al2O3\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[14].\"Slag\".\"Component\".\"Al2O3\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[15].\"Slag\".\"Component\".\"Al2O3\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[0].\"Metal\".\"Component\".\"B\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[1].\"Metal\".\"Component\".\"B\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[2].\"Metal\".\"Component\".\"B\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[3].\"Metal\".\"Component\".\"B\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[4].\"Metal\".\"Component\".\"B\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[5].\"Metal\".\"Component\".\"B\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[6].\"Metal\".\"Component\".\"B\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[7].\"Metal\".\"Component\".\"B\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[8].\"Metal\".\"Component\".\"B\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[9].\"Metal\".\"Component\".\"B\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[10].\"Metal\".\"Component\".\"B\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[11].\"Metal\".\"Component\".\"B\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[12].\"Metal\".\"Component\".\"B\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[13].\"Metal\".\"Component\".\"B\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[14].\"Metal\".\"Component\".\"B\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[15].\"Metal\".\"Component\".\"B\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[0].\"Metal\".\"Component\".\"C\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[1].\"Metal\".\"Component\".\"C\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[2].\"Metal\".\"Component\".\"C\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[3].\"Metal\".\"Component\".\"C\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[4].\"Metal\".\"Component\".\"C\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[5].\"Metal\".\"Component\".\"C\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[6].\"Metal\".\"Component\".\"C\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[7].\"Metal\".\"Component\".\"C\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[8].\"Metal\".\"Component\".\"C\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[9].\"Metal\".\"Component\".\"C\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[10].\"Metal\".\"Component\".\"C\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[11].\"Metal\".\"Component\".\"C\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[12].\"Metal\".\"Component\".\"C\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[13].\"Metal\".\"Component\".\"C\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[14].\"Metal\".\"Component\".\"C\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[15].\"Metal\".\"Component\".\"C\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[0].\"Slag\".\"Component\".\"CaF2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[1].\"Slag\".\"Component\".\"CaF2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[2].\"Slag\".\"Component\".\"CaF2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[3].\"Slag\".\"Component\".\"CaF2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[4].\"Slag\".\"Component\".\"CaF2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[5].\"Slag\".\"Component\".\"CaF2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[6].\"Slag\".\"Component\".\"CaF2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[7].\"Slag\".\"Component\".\"CaF2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[8].\"Slag\".\"Component\".\"CaF2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[9].\"Slag\".\"Component\".\"CaF2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[10].\"Slag\".\"Component\".\"CaF2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[11].\"Slag\".\"Component\".\"CaF2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[12].\"Slag\".\"Component\".\"CaF2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[13].\"Slag\".\"Component\".\"CaF2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[14].\"Slag\".\"Component\".\"CaF2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[15].\"Slag\".\"Component\".\"CaF2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[0].\"Slag\".\"Component\".\"CaO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[1].\"Slag\".\"Component\".\"CaO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[2].\"Slag\".\"Component\".\"CaO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[3].\"Slag\".\"Component\".\"CaO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[4].\"Slag\".\"Component\".\"CaO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[5].\"Slag\".\"Component\".\"CaO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[6].\"Slag\".\"Component\".\"CaO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[7].\"Slag\".\"Component\".\"CaO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[8].\"Slag\".\"Component\".\"CaO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[9].\"Slag\".\"Component\".\"CaO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[10].\"Slag\".\"Component\".\"CaO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[11].\"Slag\".\"Component\".\"CaO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[12].\"Slag\".\"Component\".\"CaO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[13].\"Slag\".\"Component\".\"CaO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[14].\"Slag\".\"Component\".\"CaO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[15].\"Slag\".\"Component\".\"CaO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[0].\"Metal\".\"Component\".\"Co\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[1].\"Metal\".\"Component\".\"Co\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[2].\"Metal\".\"Component\".\"Co\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[3].\"Metal\".\"Component\".\"Co\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[4].\"Metal\".\"Component\".\"Co\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[5].\"Metal\".\"Component\".\"Co\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[6].\"Metal\".\"Component\".\"Co\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[7].\"Metal\".\"Component\".\"Co\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[8].\"Metal\".\"Component\".\"Co\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[9].\"Metal\".\"Component\".\"Co\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[10].\"Metal\".\"Component\".\"Co\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[11].\"Metal\".\"Component\".\"Co\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[12].\"Metal\".\"Component\".\"Co\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[13].\"Metal\".\"Component\".\"Co\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[14].\"Metal\".\"Component\".\"Co\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[15].\"Metal\".\"Component\".\"Co\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[0].\"Metal\".\"Component\".\"Cr\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[1].\"Metal\".\"Component\".\"Cr\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[2].\"Metal\".\"Component\".\"Cr\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[3].\"Metal\".\"Component\".\"Cr\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[4].\"Metal\".\"Component\".\"Cr\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[5].\"Metal\".\"Component\".\"Cr\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[6].\"Metal\".\"Component\".\"Cr\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[7].\"Metal\".\"Component\".\"Cr\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[8].\"Metal\".\"Component\".\"Cr\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[9].\"Metal\".\"Component\".\"Cr\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[10].\"Metal\".\"Component\".\"Cr\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[11].\"Metal\".\"Component\".\"Cr\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[12].\"Metal\".\"Component\".\"Cr\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[13].\"Metal\".\"Component\".\"Cr\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[14].\"Metal\".\"Component\".\"Cr\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[15].\"Metal\".\"Component\".\"Cr\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[0].\"Slag\".\"Component\".\"Cr2O3\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[1].\"Slag\".\"Component\".\"Cr2O3\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[2].\"Slag\".\"Component\".\"Cr2O3\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[3].\"Slag\".\"Component\".\"Cr2O3\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[4].\"Slag\".\"Component\".\"Cr2O3\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[5].\"Slag\".\"Component\".\"Cr2O3\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[6].\"Slag\".\"Component\".\"Cr2O3\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[7].\"Slag\".\"Component\".\"Cr2O3\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[8].\"Slag\".\"Component\".\"Cr2O3\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[9].\"Slag\".\"Component\".\"Cr2O3\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[10].\"Slag\".\"Component\".\"Cr2O3\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[11].\"Slag\".\"Component\".\"Cr2O3\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[12].\"Slag\".\"Component\".\"Cr2O3\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[13].\"Slag\".\"Component\".\"Cr2O3\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[14].\"Slag\".\"Component\".\"Cr2O3\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[15].\"Slag\".\"Component\".\"Cr2O3\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[0].\"Metal\".\"Component\".\"Cu\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[1].\"Metal\".\"Component\".\"Cu\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[2].\"Metal\".\"Component\".\"Cu\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[3].\"Metal\".\"Component\".\"Cu\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[4].\"Metal\".\"Component\".\"Cu\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[5].\"Metal\".\"Component\".\"Cu\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[6].\"Metal\".\"Component\".\"Cu\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[7].\"Metal\".\"Component\".\"Cu\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[8].\"Metal\".\"Component\".\"Cu\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[9].\"Metal\".\"Component\".\"Cu\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[10].\"Metal\".\"Component\".\"Cu\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[11].\"Metal\".\"Component\".\"Cu\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[12].\"Metal\".\"Component\".\"Cu\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[13].\"Metal\".\"Component\".\"Cu\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[14].\"Metal\".\"Component\".\"Cu\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[15].\"Metal\".\"Component\".\"Cu\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[0].\"Metal\".\"Component\".\"Fe\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[1].\"Metal\".\"Component\".\"Fe\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[2].\"Metal\".\"Component\".\"Fe\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[3].\"Metal\".\"Component\".\"Fe\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[4].\"Metal\".\"Component\".\"Fe\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[5].\"Metal\".\"Component\".\"Fe\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[6].\"Metal\".\"Component\".\"Fe\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[7].\"Metal\".\"Component\".\"Fe\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[8].\"Metal\".\"Component\".\"Fe\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[9].\"Metal\".\"Component\".\"Fe\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[10].\"Metal\".\"Component\".\"Fe\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[11].\"Metal\".\"Component\".\"Fe\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[12].\"Metal\".\"Component\".\"Fe\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[13].\"Metal\".\"Component\".\"Fe\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[14].\"Metal\".\"Component\".\"Fe\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[15].\"Metal\".\"Component\".\"Fe\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[0].\"Slag\".\"Component\".\"FeO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[1].\"Slag\".\"Component\".\"FeO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[2].\"Slag\".\"Component\".\"FeO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[3].\"Slag\".\"Component\".\"FeO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[4].\"Slag\".\"Component\".\"FeO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[5].\"Slag\".\"Component\".\"FeO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[6].\"Slag\".\"Component\".\"FeO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[7].\"Slag\".\"Component\".\"FeO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[8].\"Slag\".\"Component\".\"FeO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[9].\"Slag\".\"Component\".\"FeO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[10].\"Slag\".\"Component\".\"FeO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[11].\"Slag\".\"Component\".\"FeO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[12].\"Slag\".\"Component\".\"FeO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[13].\"Slag\".\"Component\".\"FeO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[14].\"Slag\".\"Component\".\"FeO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[15].\"Slag\".\"Component\".\"FeO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[0].\"Metal\".\"Component\".\"Hf\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[1].\"Metal\".\"Component\".\"Hf\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[2].\"Metal\".\"Component\".\"Hf\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[3].\"Metal\".\"Component\".\"Hf\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[4].\"Metal\".\"Component\".\"Hf\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[5].\"Metal\".\"Component\".\"Hf\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[6].\"Metal\".\"Component\".\"Hf\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[7].\"Metal\".\"Component\".\"Hf\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[8].\"Metal\".\"Component\".\"Hf\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[9].\"Metal\".\"Component\".\"Hf\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[10].\"Metal\".\"Component\".\"Hf\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[11].\"Metal\".\"Component\".\"Hf\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[12].\"Metal\".\"Component\".\"Hf\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[13].\"Metal\".\"Component\".\"Hf\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[14].\"Metal\".\"Component\".\"Hf\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[15].\"Metal\".\"Component\".\"Hf\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[0].\"Metal\".\"Component\".\"Mg\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[1].\"Metal\".\"Component\".\"Mg\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[2].\"Metal\".\"Component\".\"Mg\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[3].\"Metal\".\"Component\".\"Mg\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[4].\"Metal\".\"Component\".\"Mg\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[5].\"Metal\".\"Component\".\"Mg\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[6].\"Metal\".\"Component\".\"Mg\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[7].\"Metal\".\"Component\".\"Mg\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[8].\"Metal\".\"Component\".\"Mg\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[9].\"Metal\".\"Component\".\"Mg\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[10].\"Metal\".\"Component\".\"Mg\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[11].\"Metal\".\"Component\".\"Mg\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[12].\"Metal\".\"Component\".\"Mg\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[13].\"Metal\".\"Component\".\"Mg\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[14].\"Metal\".\"Component\".\"Mg\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[15].\"Metal\".\"Component\".\"Mg\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[0].\"Slag\".\"Component\".\"MgO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[1].\"Slag\".\"Component\".\"MgO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[2].\"Slag\".\"Component\".\"MgO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[3].\"Slag\".\"Component\".\"MgO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[4].\"Slag\".\"Component\".\"MgO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[5].\"Slag\".\"Component\".\"MgO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[6].\"Slag\".\"Component\".\"MgO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[7].\"Slag\".\"Component\".\"MgO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[8].\"Slag\".\"Component\".\"MgO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[9].\"Slag\".\"Component\".\"MgO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[10].\"Slag\".\"Component\".\"MgO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[11].\"Slag\".\"Component\".\"MgO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[12].\"Slag\".\"Component\".\"MgO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[13].\"Slag\".\"Component\".\"MgO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[14].\"Slag\".\"Component\".\"MgO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[15].\"Slag\".\"Component\".\"MgO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[0].\"Metal\".\"Component\".\"Mn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[1].\"Metal\".\"Component\".\"Mn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[2].\"Metal\".\"Component\".\"Mn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[3].\"Metal\".\"Component\".\"Mn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[4].\"Metal\".\"Component\".\"Mn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[5].\"Metal\".\"Component\".\"Mn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[6].\"Metal\".\"Component\".\"Mn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[7].\"Metal\".\"Component\".\"Mn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[8].\"Metal\".\"Component\".\"Mn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[9].\"Metal\".\"Component\".\"Mn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[10].\"Metal\".\"Component\".\"Mn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[11].\"Metal\".\"Component\".\"Mn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[12].\"Metal\".\"Component\".\"Mn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[13].\"Metal\".\"Component\".\"Mn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[14].\"Metal\".\"Component\".\"Mn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[15].\"Metal\".\"Component\".\"Mn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[0].\"Slag\".\"Component\".\"MnO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[1].\"Slag\".\"Component\".\"MnO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[2].\"Slag\".\"Component\".\"MnO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[3].\"Slag\".\"Component\".\"MnO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[4].\"Slag\".\"Component\".\"MnO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[5].\"Slag\".\"Component\".\"MnO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[6].\"Slag\".\"Component\".\"MnO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[7].\"Slag\".\"Component\".\"MnO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[8].\"Slag\".\"Component\".\"MnO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[9].\"Slag\".\"Component\".\"MnO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[10].\"Slag\".\"Component\".\"MnO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[11].\"Slag\".\"Component\".\"MnO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[12].\"Slag\".\"Component\".\"MnO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[13].\"Slag\".\"Component\".\"MnO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[14].\"Slag\".\"Component\".\"MnO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[15].\"Slag\".\"Component\".\"MnO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[0].\"Metal\".\"Component\".\"Mo\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[1].\"Metal\".\"Component\".\"Mo\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[2].\"Metal\".\"Component\".\"Mo\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[3].\"Metal\".\"Component\".\"Mo\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[4].\"Metal\".\"Component\".\"Mo\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[5].\"Metal\".\"Component\".\"Mo\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[6].\"Metal\".\"Component\".\"Mo\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[7].\"Metal\".\"Component\".\"Mo\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[8].\"Metal\".\"Component\".\"Mo\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[9].\"Metal\".\"Component\".\"Mo\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[10].\"Metal\".\"Component\".\"Mo\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[11].\"Metal\".\"Component\".\"Mo\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[12].\"Metal\".\"Component\".\"Mo\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[13].\"Metal\".\"Component\".\"Mo\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[14].\"Metal\".\"Component\".\"Mo\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[15].\"Metal\".\"Component\".\"Mo\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[0].\"Metal\".\"Component\".\"N\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[1].\"Metal\".\"Component\".\"N\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[2].\"Metal\".\"Component\".\"N\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[3].\"Metal\".\"Component\".\"N\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[4].\"Metal\".\"Component\".\"N\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[5].\"Metal\".\"Component\".\"N\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[6].\"Metal\".\"Component\".\"N\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[7].\"Metal\".\"Component\".\"N\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[8].\"Metal\".\"Component\".\"N\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[9].\"Metal\".\"Component\".\"N\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[10].\"Metal\".\"Component\".\"N\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[11].\"Metal\".\"Component\".\"N\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[12].\"Metal\".\"Component\".\"N\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[13].\"Metal\".\"Component\".\"N\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[14].\"Metal\".\"Component\".\"N\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[15].\"Metal\".\"Component\".\"N\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[0].\"Metal\".\"Component\".\"Nb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[1].\"Metal\".\"Component\".\"Nb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[2].\"Metal\".\"Component\".\"Nb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[3].\"Metal\".\"Component\".\"Nb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[4].\"Metal\".\"Component\".\"Nb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[5].\"Metal\".\"Component\".\"Nb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[6].\"Metal\".\"Component\".\"Nb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[7].\"Metal\".\"Component\".\"Nb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[8].\"Metal\".\"Component\".\"Nb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[9].\"Metal\".\"Component\".\"Nb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[10].\"Metal\".\"Component\".\"Nb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[11].\"Metal\".\"Component\".\"Nb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[12].\"Metal\".\"Component\".\"Nb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[13].\"Metal\".\"Component\".\"Nb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[14].\"Metal\".\"Component\".\"Nb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[15].\"Metal\".\"Component\".\"Nb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[0].\"Slag\".\"Component\".\"Nb2O5\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[1].\"Slag\".\"Component\".\"Nb2O5\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[2].\"Slag\".\"Component\".\"Nb2O5\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[3].\"Slag\".\"Component\".\"Nb2O5\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[4].\"Slag\".\"Component\".\"Nb2O5\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[5].\"Slag\".\"Component\".\"Nb2O5\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[6].\"Slag\".\"Component\".\"Nb2O5\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[7].\"Slag\".\"Component\".\"Nb2O5\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[8].\"Slag\".\"Component\".\"Nb2O5\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[9].\"Slag\".\"Component\".\"Nb2O5\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[10].\"Slag\".\"Component\".\"Nb2O5\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[11].\"Slag\".\"Component\".\"Nb2O5\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[12].\"Slag\".\"Component\".\"Nb2O5\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[13].\"Slag\".\"Component\".\"Nb2O5\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[14].\"Slag\".\"Component\".\"Nb2O5\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[15].\"Slag\".\"Component\".\"Nb2O5\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[0].\"Metal\".\"Component\".\"Ni\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[1].\"Metal\".\"Component\".\"Ni\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[2].\"Metal\".\"Component\".\"Ni\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[3].\"Metal\".\"Component\".\"Ni\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[4].\"Metal\".\"Component\".\"Ni\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[5].\"Metal\".\"Component\".\"Ni\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[6].\"Metal\".\"Component\".\"Ni\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[7].\"Metal\".\"Component\".\"Ni\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[8].\"Metal\".\"Component\".\"Ni\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[9].\"Metal\".\"Component\".\"Ni\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[10].\"Metal\".\"Component\".\"Ni\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[11].\"Metal\".\"Component\".\"Ni\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[12].\"Metal\".\"Component\".\"Ni\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[13].\"Metal\".\"Component\".\"Ni\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[14].\"Metal\".\"Component\".\"Ni\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[15].\"Metal\".\"Component\".\"Ni\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[0].\"Slag\".\"Component\".\"O\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[1].\"Slag\".\"Component\".\"O\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[2].\"Slag\".\"Component\".\"O\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[3].\"Slag\".\"Component\".\"O\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[4].\"Slag\".\"Component\".\"O\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[5].\"Slag\".\"Component\".\"O\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[6].\"Slag\".\"Component\".\"O\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[7].\"Slag\".\"Component\".\"O\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[8].\"Slag\".\"Component\".\"O\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[9].\"Slag\".\"Component\".\"O\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[10].\"Slag\".\"Component\".\"O\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[11].\"Slag\".\"Component\".\"O\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[12].\"Slag\".\"Component\".\"O\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[13].\"Slag\".\"Component\".\"O\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[14].\"Slag\".\"Component\".\"O\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[15].\"Slag\".\"Component\".\"O\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[0].\"Metal\".\"Component\".\"P\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[1].\"Metal\".\"Component\".\"P\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[2].\"Metal\".\"Component\".\"P\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[3].\"Metal\".\"Component\".\"P\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[4].\"Metal\".\"Component\".\"P\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[5].\"Metal\".\"Component\".\"P\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[6].\"Metal\".\"Component\".\"P\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[7].\"Metal\".\"Component\".\"P\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[8].\"Metal\".\"Component\".\"P\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[9].\"Metal\".\"Component\".\"P\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[10].\"Metal\".\"Component\".\"P\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[11].\"Metal\".\"Component\".\"P\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[12].\"Metal\".\"Component\".\"P\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[13].\"Metal\".\"Component\".\"P\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[14].\"Metal\".\"Component\".\"P\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[15].\"Metal\".\"Component\".\"P\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[0].\"Metal\".\"Component\".\"Pb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[1].\"Metal\".\"Component\".\"Pb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[2].\"Metal\".\"Component\".\"Pb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[3].\"Metal\".\"Component\".\"Pb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[4].\"Metal\".\"Component\".\"Pb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[5].\"Metal\".\"Component\".\"Pb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[6].\"Metal\".\"Component\".\"Pb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[7].\"Metal\".\"Component\".\"Pb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[8].\"Metal\".\"Component\".\"Pb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[9].\"Metal\".\"Component\".\"Pb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[10].\"Metal\".\"Component\".\"Pb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[11].\"Metal\".\"Component\".\"Pb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[12].\"Metal\".\"Component\".\"Pb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[13].\"Metal\".\"Component\".\"Pb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[14].\"Metal\".\"Component\".\"Pb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[15].\"Metal\".\"Component\".\"Pb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[0].\"Metal\".\"Component\".\"S\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[1].\"Metal\".\"Component\".\"S\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[2].\"Metal\".\"Component\".\"S\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[3].\"Metal\".\"Component\".\"S\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[4].\"Metal\".\"Component\".\"S\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[5].\"Metal\".\"Component\".\"S\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[6].\"Metal\".\"Component\".\"S\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[7].\"Metal\".\"Component\".\"S\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[8].\"Metal\".\"Component\".\"S\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[9].\"Metal\".\"Component\".\"S\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[10].\"Metal\".\"Component\".\"S\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[11].\"Metal\".\"Component\".\"S\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[12].\"Metal\".\"Component\".\"S\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[13].\"Metal\".\"Component\".\"S\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[14].\"Metal\".\"Component\".\"S\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[15].\"Metal\".\"Component\".\"S\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[0].\"Metal\".\"Component\".\"Sb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[1].\"Metal\".\"Component\".\"Sb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[2].\"Metal\".\"Component\".\"Sb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[3].\"Metal\".\"Component\".\"Sb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[4].\"Metal\".\"Component\".\"Sb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[5].\"Metal\".\"Component\".\"Sb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[6].\"Metal\".\"Component\".\"Sb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[7].\"Metal\".\"Component\".\"Sb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[8].\"Metal\".\"Component\".\"Sb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[9].\"Metal\".\"Component\".\"Sb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[10].\"Metal\".\"Component\".\"Sb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[11].\"Metal\".\"Component\".\"Sb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[12].\"Metal\".\"Component\".\"Sb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[13].\"Metal\".\"Component\".\"Sb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[14].\"Metal\".\"Component\".\"Sb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[15].\"Metal\".\"Component\".\"Sb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[0].\"Metal\".\"Component\".\"Si\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[1].\"Metal\".\"Component\".\"Si\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[2].\"Metal\".\"Component\".\"Si\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[3].\"Metal\".\"Component\".\"Si\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[4].\"Metal\".\"Component\".\"Si\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[5].\"Metal\".\"Component\".\"Si\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[6].\"Metal\".\"Component\".\"Si\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[7].\"Metal\".\"Component\".\"Si\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[8].\"Metal\".\"Component\".\"Si\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[9].\"Metal\".\"Component\".\"Si\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[10].\"Metal\".\"Component\".\"Si\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[11].\"Metal\".\"Component\".\"Si\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[12].\"Metal\".\"Component\".\"Si\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[13].\"Metal\".\"Component\".\"Si\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[14].\"Metal\".\"Component\".\"Si\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[15].\"Metal\".\"Component\".\"Si\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[0].\"Slag\".\"Component\".\"SiO2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[1].\"Slag\".\"Component\".\"SiO2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[2].\"Slag\".\"Component\".\"SiO2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[3].\"Slag\".\"Component\".\"SiO2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[4].\"Slag\".\"Component\".\"SiO2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[5].\"Slag\".\"Component\".\"SiO2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[6].\"Slag\".\"Component\".\"SiO2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[7].\"Slag\".\"Component\".\"SiO2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[8].\"Slag\".\"Component\".\"SiO2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[9].\"Slag\".\"Component\".\"SiO2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[10].\"Slag\".\"Component\".\"SiO2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[11].\"Slag\".\"Component\".\"SiO2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[12].\"Slag\".\"Component\".\"SiO2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[13].\"Slag\".\"Component\".\"SiO2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[14].\"Slag\".\"Component\".\"SiO2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[15].\"Slag\".\"Component\".\"SiO2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[0].\"Metal\".\"Component\".\"Sn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[1].\"Metal\".\"Component\".\"Sn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[2].\"Metal\".\"Component\".\"Sn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[3].\"Metal\".\"Component\".\"Sn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[4].\"Metal\".\"Component\".\"Sn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[5].\"Metal\".\"Component\".\"Sn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[6].\"Metal\".\"Component\".\"Sn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[7].\"Metal\".\"Component\".\"Sn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[8].\"Metal\".\"Component\".\"Sn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[9].\"Metal\".\"Component\".\"Sn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[10].\"Metal\".\"Component\".\"Sn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[11].\"Metal\".\"Component\".\"Sn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[12].\"Metal\".\"Component\".\"Sn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[13].\"Metal\".\"Component\".\"Sn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[14].\"Metal\".\"Component\".\"Sn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[15].\"Metal\".\"Component\".\"Sn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[0].\"Metal\".\"Component\".\"Ti\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[1].\"Metal\".\"Component\".\"Ti\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[2].\"Metal\".\"Component\".\"Ti\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[3].\"Metal\".\"Component\".\"Ti\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[4].\"Metal\".\"Component\".\"Ti\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[5].\"Metal\".\"Component\".\"Ti\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[6].\"Metal\".\"Component\".\"Ti\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[7].\"Metal\".\"Component\".\"Ti\".\"Pct\"") },
                 },
            };
            var readRequest2 = new ReadRequest
            {
                NodesToRead = new[]
                {
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[8].\"Metal\".\"Component\".\"Ti\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[9].\"Metal\".\"Component\".\"Ti\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[10].\"Metal\".\"Component\".\"Ti\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[11].\"Metal\".\"Component\".\"Ti\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[12].\"Metal\".\"Component\".\"Ti\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[13].\"Metal\".\"Component\".\"Ti\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[14].\"Metal\".\"Component\".\"Ti\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[15].\"Metal\".\"Component\".\"Ti\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[0].\"Slag\".\"Component\".\"TiO2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[1].\"Slag\".\"Component\".\"TiO2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[2].\"Slag\".\"Component\".\"TiO2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[3].\"Slag\".\"Component\".\"TiO2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[4].\"Slag\".\"Component\".\"TiO2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[5].\"Slag\".\"Component\".\"TiO2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[6].\"Slag\".\"Component\".\"TiO2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[7].\"Slag\".\"Component\".\"TiO2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[8].\"Slag\".\"Component\".\"TiO2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[9].\"Slag\".\"Component\".\"TiO2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[10].\"Slag\".\"Component\".\"TiO2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[11].\"Slag\".\"Component\".\"TiO2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[12].\"Slag\".\"Component\".\"TiO2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[13].\"Slag\".\"Component\".\"TiO2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[14].\"Slag\".\"Component\".\"TiO2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[15].\"Slag\".\"Component\".\"TiO2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[0].\"Metal\".\"Component\".\"V\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[1].\"Metal\".\"Component\".\"V\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[2].\"Metal\".\"Component\".\"V\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[3].\"Metal\".\"Component\".\"V\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[4].\"Metal\".\"Component\".\"V\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[5].\"Metal\".\"Component\".\"V\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[6].\"Metal\".\"Component\".\"V\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[7].\"Metal\".\"Component\".\"V\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[8].\"Metal\".\"Component\".\"V\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[9].\"Metal\".\"Component\".\"V\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[10].\"Metal\".\"Component\".\"V\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[11].\"Metal\".\"Component\".\"V\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[12].\"Metal\".\"Component\".\"V\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[13].\"Metal\".\"Component\".\"V\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[14].\"Metal\".\"Component\".\"V\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[15].\"Metal\".\"Component\".\"V\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[0].\"Metal\".\"Component\".\"W\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[1].\"Metal\".\"Component\".\"W\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[2].\"Metal\".\"Component\".\"W\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[3].\"Metal\".\"Component\".\"W\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[4].\"Metal\".\"Component\".\"W\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[5].\"Metal\".\"Component\".\"W\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[6].\"Metal\".\"Component\".\"W\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[7].\"Metal\".\"Component\".\"W\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[8].\"Metal\".\"Component\".\"W\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[9].\"Metal\".\"Component\".\"W\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[10].\"Metal\".\"Component\".\"W\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[11].\"Metal\".\"Component\".\"W\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[12].\"Metal\".\"Component\".\"W\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[13].\"Metal\".\"Component\".\"W\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[14].\"Metal\".\"Component\".\"W\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[15].\"Metal\".\"Component\".\"W\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[0].\"Metal\".\"Component\".\"Zn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[1].\"Metal\".\"Component\".\"Zn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[2].\"Metal\".\"Component\".\"Zn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[3].\"Metal\".\"Component\".\"Zn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[4].\"Metal\".\"Component\".\"Zn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[5].\"Metal\".\"Component\".\"Zn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[6].\"Metal\".\"Component\".\"Zn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[7].\"Metal\".\"Component\".\"Zn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[8].\"Metal\".\"Component\".\"Zn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[9].\"Metal\".\"Component\".\"Zn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[10].\"Metal\".\"Component\".\"Zn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[11].\"Metal\".\"Component\".\"Zn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[12].\"Metal\".\"Component\".\"Zn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[13].\"Metal\".\"Component\".\"Zn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[14].\"Metal\".\"Component\".\"Zn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[15].\"Metal\".\"Component\".\"Zn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[0].\"Metal\".\"Component\".\"Zr\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[1].\"Metal\".\"Component\".\"Zr\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[2].\"Metal\".\"Component\".\"Zr\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[3].\"Metal\".\"Component\".\"Zr\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[4].\"Metal\".\"Component\".\"Zr\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[5].\"Metal\".\"Component\".\"Zr\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[6].\"Metal\".\"Component\".\"Zr\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[7].\"Metal\".\"Component\".\"Zr\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[8].\"Metal\".\"Component\".\"Zr\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[9].\"Metal\".\"Component\".\"Zr\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[10].\"Metal\".\"Component\".\"Zr\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[11].\"Metal\".\"Component\".\"Zr\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[12].\"Metal\".\"Component\".\"Zr\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[13].\"Metal\".\"Component\".\"Zr\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[14].\"Metal\".\"Component\".\"Zr\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[15].\"Metal\".\"Component\".\"Zr\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[0].\"Recovery\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[1].\"Recovery\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[2].\"Recovery\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[3].\"Recovery\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[4].\"Recovery\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[5].\"Recovery\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[6].\"Recovery\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[7].\"Recovery\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[8].\"Recovery\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[9].\"Recovery\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[10].\"Recovery\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[11].\"Recovery\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[12].\"Recovery\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[13].\"Recovery\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[14].\"Recovery\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[15].\"Recovery\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"Al\".\"PctMax\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"B\".\"PctMax\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"C\".\"PctMax\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"Ca\".\"PctMax\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"Ce\".\"PctMax\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"Co\".\"PctMax\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"Cr\".\"PctMax\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"Cu\".\"PctMax\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"Fe\".\"PctMax\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"Hf\".\"PctMax\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"Mg\".\"PctMax\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"Mn\".\"PctMax\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"Mo\".\"PctMax\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"N\".\"PctMax\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"Nb\".\"PctMax\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"Ni\".\"PctMax\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"P\".\"PctMax\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"Pb\".\"PctMax\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"S\".\"PctMax\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"Sb\".\"PctMax\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"Si\".\"PctMax\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"Sn\".\"PctMax\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"Ti\".\"PctMax\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"V\".\"PctMax\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"W\".\"PctMax\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"Zn\".\"PctMax\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"Zr\".\"PctMax\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"KQ000\".\"Output\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"Al\".\"PctMin\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"B\".\"PctMin\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"C\".\"PctMin\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"Ca\".\"PctMin\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"Ce\".\"PctMin\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"Co\".\"PctMin\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"Cr\".\"PctMin\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"Cu\".\"PctMin\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"Fe\".\"PctMin\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"Hf\".\"PctMin\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"Mg\".\"PctMin\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"Mn\".\"PctMin\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"Mo\".\"PctMin\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"N\".\"PctMin\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"Nb\".\"PctMin\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"Ni\".\"PctMin\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"P\".\"PctMin\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"Pb\".\"PctMin\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"S\".\"PctMin\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"Sb\".\"PctMin\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"Si\".\"PctMin\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"Sn\".\"PctMin\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"Ti\".\"PctMin\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"V\".\"PctMin\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"W\".\"PctMin\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"Zn\".\"PctMin\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Grade\".\"Component\".\"Zr\".\"PctMin\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue1\".\"Material\"[0].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue1\".\"Material\"[1].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue1\".\"Material\"[2].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue1\".\"Material\"[3].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue1\".\"Material\"[4].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue1\".\"Material\"[5].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue1\".\"Material\"[6].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue1\".\"Material\"[7].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue1\".\"Material\"[8].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue1\".\"Material\"[9].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue1\".\"Material\"[10].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue1\".\"Material\"[11].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue1\".\"Material\"[12].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue1\".\"Material\"[13].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue1\".\"Material\"[14].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue1\".\"Material\"[15].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue1\".\"Rate\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue2\".\"Material\"[0].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue2\".\"Material\"[1].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue2\".\"Material\"[2].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue2\".\"Material\"[3].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue2\".\"Material\"[4].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue2\".\"Material\"[5].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue2\".\"Material\"[6].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue2\".\"Material\"[7].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue2\".\"Material\"[8].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue2\".\"Material\"[9].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue2\".\"Material\"[10].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue2\".\"Material\"[11].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue2\".\"Material\"[12].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue2\".\"Material\"[13].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue2\".\"Material\"[14].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue2\".\"Material\"[15].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue2\".\"Rate\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FQ120\".\"Output\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FRC120\".\"Setpoint\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"AC000\".\"FinalNitrogen\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Practice\".\"NRE\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FIC100\".\"Output\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FIC100\".\"Gain\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"PT100\".\"Output\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FIC100\".\"Input\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FIC100\".\"Setpoint\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Practice\".\"O2_SP_FUEL\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Practice\".\"O2_SP_MAX\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Practice\".\"O2_SP_MIN\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FIC100\".\"StandbyOutput\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FIC100\".\"DerivativeTime\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"TT100\".\"Output\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FIC100\".\"IntegralTime\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FQ100\".\"Output\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Snapshot\".\"O2Total\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"OrderedMaterials\".\"Material\"[0].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"OrderedMaterials\".\"Material\"[1].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"OrderedMaterials\".\"Material\"[2].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"OrderedMaterials\".\"Material\"[3].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"OrderedMaterials\".\"Material\"[4].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"OrderedMaterials\".\"Material\"[5].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"OrderedMaterials\".\"Material\"[6].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"OrderedMaterials\".\"Material\"[7].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"OrderedMaterials\".\"Material\"[8].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"OrderedMaterials\".\"Material\"[9].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"OrderedMaterials\".\"Material\"[10].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"OrderedMaterials\".\"Material\"[11].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"OrderedMaterials\".\"Material\"[12].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"OrderedMaterials\".\"Material\"[13].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"OrderedMaterials\".\"Material\"[14].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"OrderedMaterials\".\"Material\"[15].\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Practice\".\"OverallCRE\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"System\".\"Metal\".\"Component\".\"Al\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"System\".\"Slag\".\"Component\".\"Al2O3\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"System\".\"Metal\".\"Component\".\"B\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"System\".\"Metal\".\"Component\".\"C\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"System\".\"Metal\".\"Component\".\"Ca\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"System\".\"Slag\".\"Component\".\"CaF2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"System\".\"Slag\".\"Component\".\"CaO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"System\".\"Metal\".\"Component\".\"Ce\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"System\".\"Metal\".\"Component\".\"Ca\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"System\".\"Metal\".\"Component\".\"Cr\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"System\".\"Slag\".\"Component\".\"Cr2O3\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"System\".\"Metal\".\"Component\".\"Cu\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"System\".\"Metal\".\"Component\".\"Fe\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"System\".\"Slag\".\"Component\".\"FeO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"System\".\"Metal\".\"Component\".\"Hf\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"System\".\"Metal\".\"Component\".\"Mg\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"System\".\"Slag\".\"Component\".\"MgO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"System\".\"Metal\".\"Component\".\"Mn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"System\".\"Slag\".\"Component\".\"MnO\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"System\".\"Metal\".\"Component\".\"Mo\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"System\".\"Metal\".\"Component\".\"N\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"System\".\"Metal\".\"Component\".\"Nb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"System\".\"Slag\".\"Component\".\"Nb2O5\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"System\".\"Metal\".\"Component\".\"Ni\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"System\".\"Metal\".\"Component\".\"P\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"System\".\"Metal\".\"Component\".\"Pb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"System\".\"Metal\".\"Component\".\"S\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"System\".\"Metal\".\"Component\".\"Sb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"System\".\"Metal\".\"Component\".\"Si\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"System\".\"Slag\".\"Component\".\"SiO2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"System\".\"Metal\".\"Component\".\"Sn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"System\".\"Metal\".\"Component\".\"Ti\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"System\".\"Slag\".\"Component\".\"TiO2\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"System\".\"Metal\".\"Component\".\"V\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"System\".\"Metal\".\"Component\".\"W\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"System\".\"Metal\".\"Component\".\"Zn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"System\".\"Metal\".\"Component\".\"Zr\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"PIC140\".\"Gain\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"AC000\".\"RedTempBath\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"AC000\".\"RedTime\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"AC000\".\"RedTimePreset\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FY145\".\"Output\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"PIC115\".\"Output\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"PIC115\".\"Gain\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"PIC115\".\"Input\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"PIC115\".\"Setpoint\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Practice\".\"SH_SP_FUEL\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Practice\".\"SH_SP_MAX\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Practice\".\"SH_SP_MIN\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Practice\".\"SH_SP_RED\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Practice\".\"SH_SP_STIR\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"PIC145\".\"StandbyOutput\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"PIC115\".\"DerivativeTime\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"PIC115\".\"IntegralTime\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Shell\".\"Amouth\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Shell\".\"Aref\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Shell\".\"AvgBrickThickNew\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Shell\".\"AvgBrickThickWorn\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Shell\".\"Dshell\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Shell\".\"RefrK\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Shell\".\"TfaceOnBurner\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[0].\"Component\".\"Al\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[1].\"Component\".\"Al\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[2].\"Component\".\"Al\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[3].\"Component\".\"Al\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[0].\"Component\".\"B\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[1].\"Component\".\"B\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[2].\"Component\".\"B\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[3].\"Component\".\"B\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[0].\"Component\".\"C\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[1].\"Component\".\"C\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[2].\"Component\".\"C\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[3].\"Component\".\"C\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[0].\"Component\".\"Ca\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[1].\"Component\".\"Ca\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[2].\"Component\".\"Ca\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[3].\"Component\".\"Ca\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[0].\"Component\".\"Ce\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[1].\"Component\".\"Ce\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[2].\"Component\".\"Ce\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[3].\"Component\".\"Ce\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[0].\"Component\".\"Co\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[1].\"Component\".\"Co\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[2].\"Component\".\"Co\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[3].\"Component\".\"Co\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[0].\"Component\".\"Cr\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[1].\"Component\".\"Cr\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[2].\"Component\".\"Cr\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[3].\"Component\".\"Cr\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[0].\"Component\".\"Cu\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[1].\"Component\".\"Cu\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[2].\"Component\".\"Cu\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[3].\"Component\".\"Cu\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[0].\"Component\".\"Fe\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[1].\"Component\".\"Fe\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[2].\"Component\".\"Fe\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[3].\"Component\".\"Fe\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[0].\"Component\".\"Hf\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[1].\"Component\".\"Hf\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[2].\"Component\".\"Hf\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[3].\"Component\".\"Hf\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[0].\"Component\".\"Mg\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[1].\"Component\".\"Mg\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[2].\"Component\".\"Mg\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[3].\"Component\".\"Mg\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[0].\"Component\".\"Mn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[1].\"Component\".\"Mn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[2].\"Component\".\"Mn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[3].\"Component\".\"Mn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[0].\"Component\".\"Mo\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[1].\"Component\".\"Mo\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[2].\"Component\".\"Mo\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[3].\"Component\".\"Mo\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[0].\"Component\".\"N\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[1].\"Component\".\"N\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[2].\"Component\".\"N\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[3].\"Component\".\"N\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[0].\"Component\".\"Nb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[1].\"Component\".\"Nb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[2].\"Component\".\"Nb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[3].\"Component\".\"Nb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[0].\"Component\".\"Ni\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[1].\"Component\".\"Ni\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[2].\"Component\".\"Ni\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[3].\"Component\".\"Ni\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[0].\"Component\".\"P\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[1].\"Component\".\"P\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[2].\"Component\".\"P\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[3].\"Component\".\"P\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[0].\"Component\".\"Pb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[1].\"Component\".\"Pb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[2].\"Component\".\"Pb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[3].\"Component\".\"Pb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[0].\"Component\".\"S\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[1].\"Component\".\"S\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[2].\"Component\".\"S\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[3].\"Component\".\"S\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[0].\"Component\".\"Sb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[1].\"Component\".\"Sb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[2].\"Component\".\"Sb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[3].\"Component\".\"Sb\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[0].\"Component\".\"Si\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[1].\"Component\".\"Si\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[2].\"Component\".\"Si\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[3].\"Component\".\"Si\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[0].\"Component\".\"Sn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[1].\"Component\".\"Sn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[2].\"Component\".\"Sn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[3].\"Component\".\"Sn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[0].\"Component\".\"Ti\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[1].\"Component\".\"Ti\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[2].\"Component\".\"Ti\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[3].\"Component\".\"Ti\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[0].\"Component\".\"V\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[1].\"Component\".\"V\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[2].\"Component\".\"V\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[3].\"Component\".\"V\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[0].\"Component\".\"W\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[1].\"Component\".\"W\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[2].\"Component\".\"W\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[3].\"Component\".\"W\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[0].\"Component\".\"Zn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[1].\"Component\".\"Zn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[2].\"Component\".\"Zn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[3].\"Component\".\"Zn\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[0].\"Component\".\"Zr\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[1].\"Component\".\"Zr\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[2].\"Component\".\"Zr\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[3].\"Component\".\"Zr\".\"Pct\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"AC000\".\"StirTempBath\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"AC000\".\"StirTime\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"AC000\".\"StirTimePreset\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"System\".\"T\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Heat\".\"TMax\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Heat\".\"TMin\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"TempRate\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FIC150\".\"Output\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FIC150\".\"Gain\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FIC150\".\"Input\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FIC150\".\"Setpoint\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Practice\".\"TLO2_SP_MAX\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Practice\".\"TLO2_SP_MIN\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FIC150\".\"StandbyOutput\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FIC150\".\"DerivativeTime\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FIC150\".\"IntegralTime\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"FQ150\".\"Output\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"System\".\"Metal\".\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Snapshot\".\"System\".\"Metal\".\"W\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Heat\".\"WMax\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Heat\".\"WMin\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"System\".\"Slag\".\"W\"") },

 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Heat\".\"Grade\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Heat\".\"Text\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Converter\".\"LiningId\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[0].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[1].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[2].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[3].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[4].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[5].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[6].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[7].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[8].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[9].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[10].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[11].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[12].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[13].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[14].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Materials\".\"Material\"[15].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue1\".\"Material\"[0].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue1\".\"Material\"[1].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue1\".\"Material\"[2].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue1\".\"Material\"[3].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue1\".\"Material\"[4].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue1\".\"Material\"[5].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue1\".\"Material\"[6].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue1\".\"Material\"[7].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue1\".\"Material\"[8].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue1\".\"Material\"[9].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue1\".\"Material\"[10].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue1\".\"Material\"[11].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue1\".\"Material\"[12].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue1\".\"Material\"[13].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue1\".\"Material\"[14].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue1\".\"Material\"[15].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue2\".\"Material\"[0].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue2\".\"Material\"[1].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue2\".\"Material\"[2].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue2\".\"Material\"[3].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue2\".\"Material\"[4].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue2\".\"Material\"[5].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue2\".\"Material\"[6].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue2\".\"Material\"[7].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue2\".\"Material\"[8].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue2\".\"Material\"[9].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue2\".\"Material\"[10].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue2\".\"Material\"[11].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue2\".\"Material\"[12].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue2\".\"Material\"[13].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue2\".\"Material\"[14].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"MaterialQueue2\".\"Material\"[15].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"OrderedMaterials\".\"Material\"[0].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"OrderedMaterials\".\"Material\"[1].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"OrderedMaterials\".\"Material\"[2].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"OrderedMaterials\".\"Material\"[3].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"OrderedMaterials\".\"Material\"[4].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"OrderedMaterials\".\"Material\"[5].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"OrderedMaterials\".\"Material\"[6].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"OrderedMaterials\".\"Material\"[7].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"OrderedMaterials\".\"Material\"[8].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"OrderedMaterials\".\"Material\"[9].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"OrderedMaterials\".\"Material\"[10].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"OrderedMaterials\".\"Material\"[11].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"OrderedMaterials\".\"Material\"[12].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"OrderedMaterials\".\"Material\"[13].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"OrderedMaterials\".\"Material\"[14].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"OrderedMaterials\".\"Material\"[15].\"MaterialID\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Heat\".\"Practice\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"Heat\".\"Slag\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[0].\"Text\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[1].\"Text\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[2].\"Text\"") },
 new ReadValueId { AttributeId = AttributeIds.Value, NodeId = NodeId.Parse("ns=3;s=\"SampleQueue\".\"Sample\"[3].\"Text\"") },
                },
            };

            var sw = new Stopwatch();
            sw.Restart();
            //for (int i = 0; i < 1; i++)
            //{
            var readResponse = await channel.ReadAsync(readRequest);
            foreach (var result in readResponse.Results)
            {
                Assert.IsTrue(StatusCode.IsGood(result.StatusCode));
            }
            var readResponse2 = await channel.ReadAsync(readRequest2);

            foreach (var result in readResponse2.Results)
            {
                Assert.IsTrue(StatusCode.IsGood(result.StatusCode));
            }

            sw.Stop();
            Console.WriteLine($"{sw.ElapsedMilliseconds} ms");

            Console.WriteLine($"Closing session '{channel.SessionId}'.");
            await channel.CloseAsync();
        }

        [TestMethod]
        public async Task OpcConnectorTest()
        {
            var count = 0;
            UaTcpSessionChannel channel = null;

            while (count < 60)
            {
                try
                {
                    channel = new UaTcpSessionChannel(
                            this.localDescription,
                            this.certificateStore,
                            new AnonymousIdentity(),
                            EndpointUrl,
                            SecurityPolicyUris.None,
                            loggerFactory: this.loggerFactory);

                    await channel.OpenAsync();

                    // create the keep alive subscription.
                    var subscriptionRequest = new CreateSubscriptionRequest
                    {
                        RequestedPublishingInterval = 1000f,
                        RequestedMaxKeepAliveCount = 30,
                        RequestedLifetimeCount = 30 * 3,
                        PublishingEnabled = true,
                    };
                    var subscriptionResponse = await channel.CreateSubscriptionAsync(subscriptionRequest).ConfigureAwait(false);
                    var id = subscriptionResponse.SubscriptionId;

                    var token = channel.Where(pr => pr.SubscriptionId == id).Subscribe(
                        pr =>
                        {
                            // loop thru all the data change notifications
                            var dcns = pr.NotificationMessage.NotificationData.OfType<DataChangeNotification>();
                            foreach (var dcn in dcns)
                            {
                                foreach (var min in dcn.MonitoredItems)
                                {
                                    Console.WriteLine($"sub: {pr.SubscriptionId}; handle: {min.ClientHandle}; value: {min.Value}");
                                    count++;
                                }
                            }

                        },
                        ex =>
                        {
                            Console.WriteLine($"IObserver handled exception '{ex.GetType()}'. {ex.Message}");
                        }
                    );

                    var itemsRequest = new CreateMonitoredItemsRequest
                    {
                        SubscriptionId = id,
                        ItemsToCreate = new MonitoredItemCreateRequest[]
                        {
                            new MonitoredItemCreateRequest { ItemToMonitor = new ReadValueId { NodeId = NodeId.Parse("i=2258"), AttributeId = AttributeIds.Value }, MonitoringMode = MonitoringMode.Reporting, RequestedParameters = new MonitoringParameters { ClientHandle = 12345, SamplingInterval = -1, QueueSize = 0, DiscardOldest = true } }
                        },
                    };
                    var itemsResponse = await channel.CreateMonitoredItemsAsync(itemsRequest);

                    while (channel.State == CommunicationState.Opened && count < 60)
                    {
                        await Task.Delay(1000);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Exception: {ex.GetType()}. {ex.Message}");
                }
            }

            if (channel != null)
            {
                Console.WriteLine($"Closing session '{channel.SessionId}'.");
                await channel.CloseAsync();
            }
        }

    }

}