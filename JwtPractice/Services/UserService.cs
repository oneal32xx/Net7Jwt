using System;
using JwtPractice.Authorization;
using JwtPractice.Entities;
using JwtPractice.Models;

namespace JwtPractice.Services
{
    public interface IUserService
    {
        AuthenticateResponse? Authenticate(AuthenticateRequest model);
        IEnumerable<User> GetAll();
        User? GetById(int id);
    }

    public class UserService : IUserService
    {
        // users hardcoded for simplicity, store in a db with hashed passwords in production applications
        private List<User> _users = new List<User>
    {
        new User { Id = 1, FirstName = "User01", LastName = "User01", Username = "test", Password = "test" },
        new User { Id = 2, FirstName = "User02", LastName = "User02", Username = "test02", Password = "test" },
        new User { Id = 3, FirstName = "User03", LastName = "User03", Username = "test03", Password = "test" }
    };

        private readonly IJwtUtils _jwtUtils;

        public UserService(IJwtUtils jwtUtils)
        {
            _jwtUtils = jwtUtils;
        }

        public AuthenticateResponse? Authenticate(AuthenticateRequest model)
        {
            var user = _users.SingleOrDefault(x => x.Username == model.Username && x.Password == model.Password);

            // return null if user not found
            if (user == null) return null;

            // authentication successful so generate jwt token
            var token = _jwtUtils.GenerateJwtToken(user);

            return new AuthenticateResponse(user, token);
        }

        public IEnumerable<User> GetAll()
        {
            return _users;
        }

        public User? GetById(int id)
        {
            return _users.FirstOrDefault(x => x.Id == id);
        }
    }
}

