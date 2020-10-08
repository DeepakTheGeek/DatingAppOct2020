using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DatingApp_API.Entities
{
    public class AppUser
    {
        public int Id { get; set; }

        //Added uppercase N here in order to do less code refactoring when I will Identity model.
        public string UserName { get; set; }
    }
}
