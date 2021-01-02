using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using API.Entities;
using Microsoft.EntityFrameworkCore;

namespace API.Data
{
    public class Seed
    {
        public static async Task SeedUsers(DataContext context)
        {
            if(await context.Users.AnyAsync()) return;

            var userData = await System.IO.File.ReadAllTextAsync("Data/UserSeedData.json");
            var users = JsonSerializer.Deserialize<List<AppUser>>(userData);

            foreach(var user in users)
            {
                var hmac = new HMACSHA512();
                user.UserName = user.UserName.ToLower();
                user.PassWordSalt = hmac.Key;
                user.PassWordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes("111"));

                context.Users.Add(user);
            }

            await context.SaveChangesAsync();
        }
    }
}