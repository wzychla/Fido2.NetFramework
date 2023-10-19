using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Fido2.NetFramework.Demo.Code
{
    public class DevelopmentCustomStore
    {
        private FidoDbContext _context;
        public DevelopmentCustomStore( FidoDbContext context )
        {
            this._context = context;
        }

        public bool AddUser( string username, string password )
        {
            if ( this.GetUser( username ) == null )
            {
                var user = new StoredUser
                {
                    DisplayName = username,
                    Name = username,
                    Uid = Encoding.UTF8.GetBytes( username ) // byte representation of userID is required
                };

                var pwd = new StoredPassword
                {
                    User = user,
                    Hash = BCrypt.Net.BCrypt.HashPassword( password )
                };

                this._context.Users.Add( user );
                this._context.Passwords.Add( pwd );
                this._context.SaveChanges();

                return true;
            }
            else
            {
                return false;
            }
        }

        public bool ValidateUser( string username, string password )
        {
            var user = this.GetUser( username );
            if ( user != null )
            {
                var pwd = user.Passwords.FirstOrDefault();
                if ( pwd != null )
                {
                    return BCrypt.Net.BCrypt.Verify( password, pwd.Hash );
                }
            }

            return false;
        }

        public StoredUser GetUser( string username )
        {
            return this._context.Users.FirstOrDefault( u => u.Name == username );
        }

        public IEnumerable<StoredCredential> GetCredentialsByUser( StoredUser user )
        {
            return this._context.Credentials.Where( c => c.UserId == user.Uid );
        }

        public StoredCredential GetCredentialById( byte[] id )
        {

            return this._context.Credentials.FirstOrDefault( c => c.DescriptorId == id );
        }

        public IEnumerable<StoredCredential> GetCredentialsByUserHandle( byte[] userHandle )
        {
            return this._context.Credentials.Where( c => c.UserHandle == userHandle );
        }

        public void UpdateCounter( byte[] credentialId, uint counter )
        {
            var cred = this.GetCredentialById( credentialId );
            if ( cred != null )
            {
                cred.SignatureCounter = counter;
                this._context.SaveChanges();
            }
        }

        public void AddCredentialToUser( StoredUser user, StoredCredential credential )
        {
            credential.UserId = user.Uid;
            this._context.Credentials.Add( credential );
            this._context.SaveChanges();
        }

        public IEnumerable<StoredUser> GetUsersByCredentialId( byte[] credentialId )
        {
            // our in-mem storage does not allow storing multiple users for a given credentialId. Yours shouldn't either.
            var cred = this.GetCredentialById( credentialId);

            if ( cred == null )
            {
                return Enumerable.Empty<StoredUser>();
            }

            return this._context.Users.Where( u => u.Uid == cred.UserId );
        }
    }

    /*
    public class DevelopmentInMemoryCustomStore
    {
        private readonly ConcurrentDictionary<string, Fido2User> _storedUsers = new();
        private readonly List<StoredCredential> _storedCredentials = new();

        public Fido2User GetOrAddUser( string username, Func<Fido2User> addCallback )
        {
            return _storedUsers.GetOrAdd( username, addCallback() );
        }

        public Fido2User? GetUser( string username )
        {
            _storedUsers.TryGetValue( username, out var user );
            return user;
        }

        public List<StoredCredential> GetCredentialsByUser( Fido2User user )
        {
            return _storedCredentials.Where( c => c.UserId.AsSpan().SequenceEqual( user.Uid ) ).ToList();
        }

        public StoredCredential? GetCredentialById( byte[] id )
        {
            return _storedCredentials.FirstOrDefault( c => c.Descriptor.Id.AsSpan().SequenceEqual( id ) );
        }

        public Task<List<StoredCredential>> GetCredentialsByUserHandleAsync( byte[] userHandle, CancellationToken cancellationToken = default )
        {
            return Task.FromResult( _storedCredentials.Where( c => c.UserHandle.AsSpan().SequenceEqual( userHandle ) ).ToList() );
        }

        public void UpdateCounter( byte[] credentialId, uint counter )
        {
            var cred = _storedCredentials.First(c => c.Descriptor.Id.AsSpan().SequenceEqual(credentialId));
            cred.SignatureCounter = counter;
        }

        public void AddCredentialToUser( Fido2User user, StoredCredential credential )
        {
            credential.UserId = user.Uid;
            _storedCredentials.Add( credential );
        }

        public Task<List<Fido2User>> GetUsersByCredentialIdAsync( byte[] credentialId, CancellationToken cancellationToken = default )
        {
            // our in-mem storage does not allow storing multiple users for a given credentialId. Yours shouldn't either.
            var cred = _storedCredentials.FirstOrDefault(c => c.Descriptor.Id.AsSpan().SequenceEqual(credentialId));

            if ( cred is null )
                return Task.FromResult( new List<Fido2User>() );

            return Task.FromResult( _storedUsers.Where( u => u.Value.Uid.SequenceEqual( cred.UserId ) ).Select( u => u.Value ).ToList() );
        }
    }
    */
}