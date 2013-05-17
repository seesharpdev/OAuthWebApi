﻿using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;

using DotNetOpenAuth.Messaging.Bindings;

using OAuthWebApi.Models;

namespace OAuthWebApi.Infrastructure
{
    /// <summary>
    /// A database-persisted nonce store.
    /// </summary>
    public class DatabaseKeyNonceStore : INonceStore, ICryptoKeyStore
    {
        #region INonceStore Members

        /// <summary>
        /// Stores a given nonce and timestamp.
        /// </summary>
        /// <param name="context">The context, or namespace, within which the
        /// <paramref name="nonce"/> must be unique.
        /// The context SHOULD be treated as case-sensitive.
        /// The value will never be <c>null</c> but may be the empty string.</param>
        /// <param name="nonce">A series of random characters.</param>
        /// <param name="timestampUtc">The UTC timestamp that together with the nonce string make it unique
        /// within the given <paramref name="context"/>.
        /// The timestamp may also be used by the data store to clear out old nonces.</param>
        /// <returns>
        /// True if the context+nonce+timestamp (combination) was not previously in the database.
        /// False if the nonce was stored previously with the same timestamp and context.
        /// </returns>
        /// <remarks>
        /// The nonce must be stored for no less than the maximum time window a message may
        /// be processed within before being discarded as an expired message.
        /// This maximum message age can be looked up via the
        /// <see cref="DotNetOpenAuth.Configuration.MessagingElement.MaximumMessageLifetime"/>
        /// property, accessible via the <see cref="DotNetOpenAuth.Configuration.DotNetOpenAuthSection.Configuration"/>
        /// property.
        /// </remarks>
        public bool StoreNonce(string context, string nonce, DateTime timestampUtc)
        {

            // ### TODO: If i don't check if the nonce is there and return true, it breaks.
            if (MvcApplication.DataContext.Nonces.Any(n => n.Code == nonce && n.Context == context && n.Timestamp == timestampUtc)) return true;

            MvcApplication.DataContext.AddToNonces(new Nonce { Context = context, Code = nonce, Timestamp = timestampUtc });

            try
            {
                MvcApplication.DataContext.SaveChanges();
                return true;
            }
            catch (System.Data.Linq.DuplicateKeyException)
            {
                return false;
            }
            catch (SqlException)
            {
                return false;
            }
        }

        #endregion

        #region ICryptoKeyStore Members

        public CryptoKey GetKey(string bucket, string handle)
        {
            // It is critical that this lookup be case-sensitive, which can only be configured at the database.
            var keys = new List<CryptoKey>();

            var ms = from key in MvcApplication.DataContext.SymmetricCryptoKeys
                     where key.Bucket == bucket && key.Handle == handle
                     select key;

            foreach (var m in ms)
            {
                var ck = new CryptoKey(m.Secret, m.ExpiresUtc.AsUtc());
                keys.Add(ck);
            }

            return keys.FirstOrDefault();
        }

        public IEnumerable<KeyValuePair<string, CryptoKey>> GetKeys(string bucket)
        {
            var cryptokeys = new List<KeyValuePair<string, CryptoKey>>();

            var keys = from key in MvcApplication.DataContext.SymmetricCryptoKeys
                       where key.Bucket == bucket
                       orderby key.ExpiresUtc descending
                       select key;

            foreach (var key in keys)
            {
                var kvp = new KeyValuePair<string, CryptoKey>(key.Handle, new CryptoKey(key.Secret, key.ExpiresUtc.AsUtc()));
                cryptokeys.Add(kvp);
            }

            return cryptokeys;
        }

        public void StoreKey(string bucket, string handle, CryptoKey key)
        {
            var keyRow = new SymmetricCryptoKey
                {
                    Bucket = bucket,
                    Handle = handle,
                    Secret = key.Key,
                    ExpiresUtc = key.ExpiresUtc,
                };

            MvcApplication.DataContext.AddToSymmetricCryptoKeys(keyRow);
            MvcApplication.DataContext.SaveChanges();
        }

        public void RemoveKey(string bucket, string handle)
        {
            var match = MvcApplication.DataContext.SymmetricCryptoKeys.FirstOrDefault(k => k.Bucket == bucket && k.Handle == handle);

            if (match != null)
            {
                MvcApplication.DataContext.SymmetricCryptoKeys.DeleteObject(match);
            }
        }

        #endregion
    }
}