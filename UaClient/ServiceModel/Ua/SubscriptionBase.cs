// Copyright (c) Converter Systems LLC. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections;
using System.Collections.Generic;
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
    /// A base class that subscribes to receive data changes and events from an OPC UA server.
    /// </summary>
    public abstract class SubscriptionBase : INotifyPropertyChanged, INotifyDataErrorInfo, ISetDataErrorInfo
    {
        private readonly ErrorsContainer<string> errors;
        private readonly IProgress<CommunicationState> progress;
        private CommunicationState state = CommunicationState.Created;

        /// <summary>
        /// Initializes a new instance of the <see cref="SubscriptionBase"/> class.
        /// </summary>
        public SubscriptionBase()
            : this(UaApplication.Current)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SubscriptionBase"/> class.
        /// </summary>
        /// <param name="application">The UaApplication.</param>
        public SubscriptionBase(UaApplication application)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            this.errors = new ErrorsContainer<string>(p => this.ErrorsChanged?.Invoke(this, new DataErrorsChangedEventArgs(p)));
            this.progress = new Progress<CommunicationState>(s => this.State = s);

            application.Subscribe(this);
        }

        /// <summary>
        /// Gets the <see cref="CommunicationState"/>.
        /// </summary>
        public CommunicationState State
        {
            get { return this.state; }
            private set { this.SetProperty(ref this.state, value); }
        }

        /// <summary>
        /// Requests a Refresh of all Conditions.
        /// </summary>
        /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
        //public async Task<StatusCode> ConditionRefreshAsync()
        //{
        //    if (this.State != CommunicationState.Opened)
        //    {
        //        return StatusCodes.BadServerNotConnected;
        //    }

        //    return await this.InnerChannel.ConditionRefreshAsync(this.SubscriptionId);
        //}

        /// <summary>
        /// Acknowledges a condition.
        /// </summary>
        /// <param name="condition">an AcknowledgeableCondition.</param>
        /// <param name="comment">a comment.</param>
        /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
        //public async Task<StatusCode> AcknowledgeAsync(AcknowledgeableCondition condition, LocalizedText comment = null)
        //{
        //    if (condition == null)
        //    {
        //        throw new ArgumentNullException(nameof(condition));
        //    }

        //    if (this.State != CommunicationState.Opened)
        //    {
        //        return StatusCodes.BadServerNotConnected;
        //    }

        //    return await this.InnerChannel.AcknowledgeAsync(condition, comment);
        //}

        /// <inheritdoc/>
        public event PropertyChangedEventHandler PropertyChanged;

        /// <summary>
        /// Gets the inner channel.
        /// </summary>
        //protected UaTcpSessionChannel InnerChannel
        //{
        //    get
        //    {
        //        if (this.innerChannel == null)
        //        {
        //            throw new ServiceResultException(StatusCodes.BadServerNotConnected);
        //        }

        //        return this.innerChannel;
        //    }
        //}

        /// <summary>
        /// Sets the property value and notifies listeners that the property value has changed.
        /// </summary>
        /// <typeparam name="T">Type of the property.</typeparam>
        /// <param name="storage">Reference to a storage field.</param>
        /// <param name="value">The new value.</param>
        /// <param name="propertyName">Name of the property used to notify listeners. This
        /// value is optional and can be provided automatically when invoked from compilers that
        /// support CallerMemberName.</param>
        /// <returns>True if the value changed, otherwise false.</returns>
        protected virtual bool SetProperty<T>(ref T storage, T value, [CallerMemberName] string propertyName = null)
        {
            if (object.Equals(storage, value))
            {
                return false;
            }

            storage = value;
            this.NotifyPropertyChanged(propertyName);
            return true;
        }

        /// <summary>
        /// Notifies listeners that the property value has changed.
        /// </summary>
        /// <param name="propertyName">Name of the property used to notify listeners. This
        /// value is optional and can be provided automatically when invoked from compilers
        /// that support <see cref="T:System.Runtime.CompilerServices.CallerMemberNameAttribute" />.</param>
        protected virtual void NotifyPropertyChanged([CallerMemberName] string propertyName = null)
        {
            this.PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        /// <summary>
        /// Occurs when the validation errors have changed for a property or entity.
        /// </summary>
        public event EventHandler<DataErrorsChangedEventArgs> ErrorsChanged;

        /// <summary>
        /// Gets a value indicating whether the entity has validation errors.
        /// </summary>
        public bool HasErrors
        {
            get { return this.errors.HasErrors; }
        }

        /// <summary>
        /// Gets the validation errors for a specified property or for the entire entity.
        /// </summary>
        /// <param name="propertyName">The name of the property to retrieve validation errors for, or null or System.String.Empty to retrieve entity-level errors.</param>
        /// <returns>The validation errors for the property or entity.</returns>
        public IEnumerable GetErrors(string propertyName)
        {
            return this.errors.GetErrors(propertyName);
        }

        /// <summary>
        /// Sets the validation errors for a specified property or for the entire entity.
        /// </summary>
        /// <param name="propertyName">The name of the property, or null or System.String.Empty to set entity-level errors.</param>
        /// <param name="errors">The validation errors for the property or entity.</param>
        void ISetDataErrorInfo.SetErrors(string propertyName, IEnumerable<string> errors)
        {
            this.errors.SetErrors(propertyName, errors);
        }
    }
}