// Copyright (c) Converter Systems LLC. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Org.BouncyCastle.Crypto.Parameters;

namespace Workstation.ServiceModel.Ua
{
    public class X509Identity : IUserIdentity
    {
        public X509Identity(byte[] certificate, RsaKeyParameters key)
        {
            this.Certificate = certificate;
            this.Key = key;
        }

        public byte[] Certificate { get; }

        public RsaKeyParameters Key { get; }
    }
}
