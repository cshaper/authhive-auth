using AuthHive.Auth.Data.Context;
using AuthHive.Core.Interfaces.Base;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Data
{
    public class UnitOfWork : IUnitOfWork
    {
        private readonly AuthDbContext _context;
        private IDbContextTransaction? _transaction;

        public UnitOfWork(AuthDbContext context)
        {
            _context = context;
        }

        public Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
        {
            return _context.SaveChangesAsync(cancellationToken);
        }

        public async Task BeginTransactionAsync(CancellationToken cancellationToken = default)
        {
            if (_transaction != null)
            {
                return;
            }
            _transaction = await _context.Database.BeginTransactionAsync(cancellationToken);
        }

        public async Task CommitTransactionAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                await _context.SaveChangesAsync(cancellationToken);
                await _transaction?.CommitAsync(cancellationToken)!;
            }
            catch
            {
                await RollbackTransactionAsync(cancellationToken);
                throw;
            }
            finally
            {
                if (_transaction != null)
                {
                    _transaction.Dispose();
                    _transaction = null;
                }
            }
        }

        public async Task RollbackTransactionAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                await _transaction?.RollbackAsync(cancellationToken)!;
            }
            finally
            {
                if (_transaction != null)
                {
                    _transaction.Dispose();
                    _transaction = null;
                }
            }
        }

        public TRepository GetRepository<TRepository>() where TRepository : class
        {
            // This is a simplified implementation. A more robust version might use a dictionary to cache repository instances.
            var repo = Activator.CreateInstance(typeof(TRepository), _context);
            if (repo == null)
            {
                throw new InvalidOperationException($"Repository of type {typeof(TRepository).Name} could not be created.");
            }
            return (TRepository)repo;
        }

        public bool HasChanges()
        {
            return _context.ChangeTracker.HasChanges();
        }

        public void ClearChangeTracker()
        {
            _context.ChangeTracker.Clear();
        }

        public void Dispose()
        {
            _transaction?.Dispose();
            _context.Dispose();
            GC.SuppressFinalize(this);
        }

        public bool HasActiveTransaction => _transaction != null;
    }
}