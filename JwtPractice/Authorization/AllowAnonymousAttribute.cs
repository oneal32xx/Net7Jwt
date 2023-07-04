using System;
namespace JwtPractice.Authorization
{
    [AttributeUsage(AttributeTargets.Method)]
    public class AllowAnonymousAttribute: Attribute
    {
		public AllowAnonymousAttribute()
		{
		}
	}
}

