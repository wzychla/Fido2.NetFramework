using Fido2NetLib;
using Fido2NetLib.Objects;
using System;
using System.Collections.Generic;
using System.Data.Entity;

namespace Fido2.NetFramework.Demo
{
    public class FidoDbContext : DbContext
    {
        public FidoDbContext() { }

        public FidoDbContext( string cs ) : base( cs ) { }

        
        public DbSet<StoredCredential> Credentials { get; set; }
        public DbSet<StoredPassword> Passwords { get; set; }
        public DbSet<StoredUser> Users { get; set; }
    }

    public class StoredUser
    {
        public StoredUser()
        {

        }

        public StoredUser( Fido2User fido )
        {
            Name = fido.Name;
            DisplayName = fido.DisplayName;
            Uid = fido.Id;
        }

        public long ID { get; set; }
        public string Name { get; set; }

        public byte[] Uid { get; set; }

        public string DisplayName { get; set; }

        public virtual ICollection<StoredPassword> Passwords { get; set; }

        public Fido2User ToFidoUser()
        {
            return new Fido2User()
            {
                DisplayName = this.DisplayName,
                Id          = this.Uid,
                Name        = this.Name
            };
        }
    }

    public class StoredPassword
    {
        public long ID { get; set; }

        public string Hash { get; set; }

        public virtual StoredUser User { get; set; }
    }

    public class StoredCredential
    {
        public long ID { get; set; }
        public byte[] UserId { get; set; }
        public byte[] DescriptorId { get; set; }
        public byte[] PublicKey { get; set; }
        public byte[] UserHandle { get; set; }
        public uint SignatureCounter { get; set; }
        public string CredType { get; set; }
        public DateTime RegDate { get; set; }
        public Guid AaGuid { get; set; }
    }
}
