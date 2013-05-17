﻿using System;
using System.Collections.Generic;
using System.Web.Http;

namespace OAuthWebApi.Controllers
{
    [Authorize]
    public class ValuesController : ApiController
    {
        // GET /api/values
        public IEnumerable<string> Get()
        {
            return new[] { "value1", DateTime.UtcNow.ToString() };
        }

        // GET /api/values/5
        public string Get(int id)
        {
            return "value";
        }

        // POST /api/values
        public void Post(string value)
        {
        }

        // PUT /api/values/5
        public void Put(int id, string value)
        {
        }

        // DELETE /api/values/5
        public void Delete(int id)
        {
        }
    }   
}