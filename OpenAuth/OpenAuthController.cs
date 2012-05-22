//using System;
//using System.Collections.Concurrent;
//using System.Collections.Generic;
//using System.Linq;
//using System.Security.Principal;
//using System.Text;
//using System.Web;
//using System.Web.Mvc;
//using System.Web.SessionState;
//using OpenAuth.Consumers;
//using OpenAuth.Models;

//namespace OpenAuth
//{
//    public class OpenAuthController : Controller
//    {
//        public ActionResult Callback(string guid)
//        {
//            if (guid == null)
//                throw new OpenAuthException { Error = OpenAuthErrorType.CrossSiteRequestForgery };

//            OpenAuthSession session;
//            OpenAuthSessionRepository.Sessions.TryRemove(guid, out session);

//            if (session == null)
//                throw new OpenAuthException { Error = OpenAuthErrorType.CrossSiteRequestForgery };

//            OpenAuthAccessToken accessToken;
//            OpenAuthUser userInfo;
//            switch (session.Provider) {
//                case OpenAuthProvider.Facebook:
//                    accessToken = FacebookClient.ProcessCallback();
//                    userInfo = FacebookClient.GetUserInfo(accessToken.Token);
//                    break;
//                case OpenAuthProvider.Twitter:
//                    accessToken = TwitterClient.ProcessCallback();
//                    userInfo = TwitterClient.GetUserInfo(accessToken.Token, accessToken.TokenSecret);
//                    break;
//                default:
//                    throw new NotImplementedException(session.Provider.ToString());
//            }

//            return session.Callback(userInfo, accessToken, User, Session, Response);
//        }
//    }
//}