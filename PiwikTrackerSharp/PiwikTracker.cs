using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Globalization;

namespace PiwikTrackerSharp
{
    public class SimplePiwikTracker 
    {


        public static int VERSION = 1;
        public static int MAX_CUSTOM_VARIABLES = 5;
        public static int MAX_CUSTOM_VARIABLE_LENGTH = 100;
        private Uri apiurl;
        /* Debug only */
        private String debug_append_url = "";
        // has to be set in the Request to the server 'HTTP_USER_AGENT'
        private String userAgent;
        // has to be set in the request to the server 'HTTP_ACCEPT_LANGUAGE'
        private String language;
        private DateTimeOffset localTime;

        private Dictionary<EBrowserPlugins, bool> plugins =
            Enum.GetValues(typeof (EBrowserPlugins)).Cast<EBrowserPlugins>().ToDictionary(k => k, k => false);

        private Dictionary<String, String> customVar =
            new Dictionary<String, String>(SimplePiwikTracker.MAX_CUSTOM_VARIABLES);

        private String customData;
        private DateTimeOffset forcedDateTimeOffsettime;
        private String token_auth;
        private Cookie requestCookie;
        private int idSite;
        private String pageUrl;
        private String ip;
        private String visitorId;
        private Uri urlReferer;
        private int width;
        private int height;

        public SimplePiwikTracker(String apiUrl)
        {
            this.setApiurl(apiUrl);
            this.setVisitorId(this.md5(Guid.NewGuid().ToString()).Substring(0, 16));
        }

        /**
     * Builds a PiwikTracker object, used to track visits, pages and Goal conversions 
     * for a specific website, by using the Piwik Tracking API.
     * 
     * @param idSite Id of the site to be tracked
     * @param apiUrl points to Uri of the tracker server
     * @throws PiwikException 
     */

        public SimplePiwikTracker(int idSite, String apiUrl, HttpRequestBase request)
            : this(apiUrl)
        {
            this.idSite = idSite;
            this.readRequestInfos(request);
        }

        /**
     * Returns the visitor id of this tracker object.
     * @return the visitor id as a String object
     */

        public String getVisitorId()
        {
            return this.visitorId;
        }

        /**
     * Sets information to the tracker from the request. the information
     * pageurl, urlreferer, useragend, ip, language and the piwik cookie will be
     * read.
     * 
     * @param request
     * @throws UriFormatException if the urls read could not be parsed to 
     * an url object
     */

        public void readRequestInfos(HttpRequestBase request)
        {
            if (request != null)
            {
                this.setUrlReferer(request.Headers["Referer"]);
                this.setUserAgent(request.Headers["User-Agent"]);
                this.setPageUrl(request.Url.ToString());
                this.setIp(GetIPAddress(request));
                this.setAcceptLanguage(request.Headers["Accept-Language"]);
                if (request.Cookies != null)
                {
                    foreach (var cookieKey in request.Cookies.AllKeys)
                    {
                        if (cookieKey == "piwik_visitor")
                        {
                            this.setRequestCookie(new Cookie(cookieKey, request.Cookies[cookieKey].Value));
                        }
                    }
                }
            }
        }

        protected string GetIPAddress(HttpRequestBase request)
        {

            string ipAddress = request.ServerVariables["HTTP_X_FORWARDED_FOR"];

            if (!string.IsNullOrEmpty(ipAddress))
            {
                string[] addresses = ipAddress.Split(',');
                if (addresses.Length != 0)
                {
                    return addresses[0];
                }
            }

            return request.ServerVariables["REMOTE_ADDR"];
        }

        /**
     * Sets the language set in the browser request. 
     * This will be used to determine where the request comes from.
     * 
     * @param acceptLanguage as a string object in ISO 639 code
     */

        public void setAcceptLanguage(String language)
        {
            this.language = language;
        }

        /**
     * Sets the language set in the browser request. 
     * This will be used to determine where the request comes from.
     * 
     * @param acceptLanguage as a locale object
     */

      
        /**
     * Sets the url of the piwik installation the tracker will track to.
     * 
     * The given string should be in the format of RFC2396. The string will be
     * converted to an url with no other url as its context. If this is not 
     * wanted, create an own url object and use the equivalent function to this.
     * 
     * @param apiurl as a string object
     */

        public void setApiurl(String apiurl)
        {
            try
            {
                this.setApiurl(new Uri(apiurl));
            }
            catch (UriFormatException e)
            {
                throw new PiwikException("Could not parse given url: " + apiurl, e);
            }
        }

        /**
     * Sets the url of the piwik installation the tracker will track to.
     * 
     * @param apiurl as a Uri object
     */

        public void setApiurl(Uri apiurl)
        {
            if (apiurl == null)
            {
                throw new PiwikException("You must provide the Piwik Tracker Uri!");
            }
            string path = String.Format("{0}{1}{2}{3}", apiurl.Scheme, Uri.SchemeDelimiter, apiurl.Authority, apiurl.AbsolutePath);
            if (path.EndsWith("piwik.php") || path.EndsWith("piwik-proxy.php"))
            {
                this.apiurl = apiurl;
            }
            else
            {
                this.apiurl = new Uri(apiurl, path + "piwik.php");
            }
        }

        /**
     * 
     * @param customData the data as a string object
     */

        public void setCustomData(String customData)
        {
            this.customData = customData;
        }

        /**
     * Sets a string for debugging usage. Please only call this function if
     * debugging is wanted.
     * @param debug_append_url 
     */

        public void setDebug_append_url(String debug_append_url)
        {
            this.debug_append_url = debug_append_url == null ? "" : debug_append_url;
        }

        /**
     * Sets the time the request was send.
     * 
     * @param forcedDateTimeOffsettime the time as a DateTimeOffset object
     */

        public void setForcedDateTimeOffsettime(DateTimeOffset forcedDateTimeOffsettime)
        {
            this.forcedDateTimeOffsettime = forcedDateTimeOffsettime;
        }

        /**
     * Sets the ip from which the request was send.
     * 
     * @param ip the ip as a string object
     */

        public void setIp(String ip)
        {
            this.ip = ip;
        }

        public void setIdSite(int idSite)
        {
            this.idSite = idSite;
        }

        public void setPageUrl(string pageUrl)
        {
            this.pageUrl = pageUrl;
        }

        /**
     * Sets the screen resolution of the browser which sends the request
     * 
     * @param width the screen width as an int value
     * @param height the screen height as an int value
     */

        public void setResolution(int width, int height)
        {
            this.width = width;
            this.height = height;
        }

        /**
     * Sets the piwik cookie of the requester. Therefor the name of the cookie
     * has to be 'piwik_visitor'. All other cookies and null as parameter will
     * reset the cookie.
     * 
     * @param requestCookie the piwik cookie as cookie object
     * @return <code>true</code> if the cookie was set otherwise false
     */

        public bool setRequestCookie(Cookie requestCookie)
        {
            Cookie tobeset = null;
            if (requestCookie != null && requestCookie.Name == ("piwik_visitor"))
            {
                tobeset = requestCookie;
            }
            this.requestCookie = tobeset;
            return this.requestCookie != null;
        }

        /**
     * Sets the authentication string from the piwik installation for access 
     * of piwik data.
     * 
     * @param token_auth the token as a string object
     */

        public void setToken_auth(String token_auth)
        {
            this.token_auth = token_auth;
        }

        /**
     * Sets the referer url of the request. This will be used to determine where
     * the request comes from.
     * 
     * The given string should be in the format of RFC2396. The string will be
     * converted to an url with the apiurl as its context. This will makes relative
     * urls to the apiurl possible. If this is not wanted, create an own url object
     * and use the equivalent function to this.
     * 
     * @param urlReferer the referer url as a string object
     */

        public void setUrlReferer(String urlReferer)
        {
            try
            {
                if (urlReferer == null)
                {
                    this.urlReferer = null;
                }
                else
                {
                    this.urlReferer = new Uri(apiurl, urlReferer);
                }
            }
            catch (UriFormatException e)
            {
                throw new PiwikException("Could not parse referer url: " + urlReferer, e);
            }
        }

        /**
     * Sets the referer url of the request. This will be used to determine where
     * the request comes from.
     * 
     * @param urlReferer the referer url as a url object
     */

        public void setUrlReferer(Uri urlReferer)
        {
            this.urlReferer = urlReferer;
        }

        /**
     * Sets the user agent identification of the requester. This will be used to
     * determine with which kind of client the request was send.
     * 
     * @param userAgent the user agent identification as a string object
     */

        public void setUserAgent(String userAgent)
        {
            this.userAgent = userAgent;
        }

        /**
     * Sets the id of the requester. This will be used to determine if the requester
     * is a returning visitor.
     * 
     * @param visitorId the id of the visitor as a string object
     */

        public void setVisitorId(String visitorId)
        {
            this.visitorId = visitorId;
        }

        /**
     * Sets visitor custom variables; ignoring fixed order (differs from PHP version).
     * still the order shouldn't change anyway.
     * 
     * @param name Custom variable name
     * @param value Custom variable value
     * @return the count of the custom parameters
     * @throws PiwikException when the maximum size of variables is reached or the name or the value is longer as the maximum variable length
     */

        public int setCustomVariable(String name, String value)
        {
            if (!this.customVar.ContainsKey(name) &&
                this.customVar.Count >= SimplePiwikTracker.MAX_CUSTOM_VARIABLE_LENGTH)
            {
                throw new PiwikException("Max size of custom variables are reached. You can only put up to " +
                                         SimplePiwikTracker.MAX_CUSTOM_VARIABLE_LENGTH +
                                         " custom variables to a request.");
            }

            if (name.Length > MAX_CUSTOM_VARIABLE_LENGTH)
            {
                throw new PiwikException("Parameter \"name\" exceeds maximum length of " + MAX_CUSTOM_VARIABLE_LENGTH +
                                         ". Given length is " + name.Length);
            }

            if (value.Length > MAX_CUSTOM_VARIABLE_LENGTH)
            {
                throw new PiwikException("Parameter \"value\" exceeds maximum length of " + MAX_CUSTOM_VARIABLE_LENGTH +
                                         ". Given length is " + name.Length);
            }

            this.customVar[name] = (value);
            return this.customVar.Count;
        }

        /**
     * Resets all given custom variables.
     */

        public void clearCustomVariables()
        {
            this.customVar.Clear();
        }

        /**
     * Adds a browser plugin to the list to detected plugins. With the boolean 
     * flag is set whether the plugin is enabled or disabled.
     * 
     * @param plugin the plugin which was detected
     * @param enabled <code>true</code> is the plugin is enabled otherwise <code>false</code>
     */

        public void setPlugin(EBrowserPlugins plugin, bool enabled)
        {
            this.plugins[plugin] = (enabled);
        }

        /**
     * Resets all given browser plugins.
     */

        public void clearPluginList()
        {
            this.plugins.Clear();
        }

        /**
     * Sets local visitor time.
     * 
     * @param time the local time as a string object in the format HH:MM:SS
     */

        public void setLocalTime(String time)
        {
            DateTimeOffset dateTimeOffset = DateTimeOffset.UtcNow;
            if (time != null)
            {
                try
                {
                    dateTimeOffset = DateTimeOffset.ParseExact(time, "HH:mm:ss", null);
                }
                catch (FormatException e)
                {
                    throw new PiwikException(
                        "Error while parsing given time '" + time + "' to a DateTimeOffset object", e);
                }
            }
            this.setLocalTime(dateTimeOffset);
        }

        /**
     * Sets local visitor time. With null you can reset the time.
     * 
     * @param time the local time as a DateTimeOffset object
     */

        public void setLocalTime(DateTimeOffset time)
        {
            this.localTime = time;
        }

        /**
     * Returns the uery part for the url with all parameters from all given 
     * informations set to this tracker.
     * This function is called in the defined url for the tacking purpose.
     * 
     * @return the query part for the url as string object
     */

        public String getGeneralQuery()
        {
            Uri rootUri = this.apiurl;
            String rootQuery = rootUri.Query;
            String withIdsite = this.addParameter(rootQuery, "idsite", this.idSite);
            String withRec = this.addParameter(withIdsite, "rec", 1); // what ever this is
            String withApiVersion = this.addParameter(withRec, "apiv", SimplePiwikTracker.VERSION);
            String withUri = this.addParameter(withApiVersion, "url", this.pageUrl);
            String withUriReferer = this.addParameter(withUri, "urlref", this.urlReferer);
            String withVisitorId = this.addParameter(withUriReferer, "_id", this.visitorId);
            String withReferer = this.addParameter(withVisitorId, "ref", this.urlReferer);
            String withRefererForcedTimestamp = this.addParameter(withReferer, "_refts", this.forcedDateTimeOffsettime);
            String withIp = this.addParameter(withRefererForcedTimestamp, "cip", this.ip);
            String withForcedTimestamp = this.addParameter(withIp, "cdt",
                                                           forcedDateTimeOffsettime == null
                                                               ? null
                                                               : forcedDateTimeOffsettime.ToString("yyyyMMdd HH:mm:ssZ"));
            String withAuthtoken = this.addParameter(withForcedTimestamp, "token_auth", this.token_auth);
            String withPlugins = withAuthtoken;
            foreach (var  entry in this.plugins)
            {
                withPlugins = this.addParameter(withPlugins, entry.Key.ToString() + "=true", entry.Value);
            }
            String withLocalTime;
            if (this.localTime == null)
            {
                withLocalTime = withPlugins;
            }
            else
            {
                var time = this.localTime;
                String withHour = this.addParameter(withPlugins, "h", localTime.Hour);
                String withMinute = this.addParameter(withHour, "m", localTime.Minute);
                withLocalTime = this.addParameter(withMinute, "s", localTime.Second);
            }
            String withResolution;
            if (this.width > 0 && this.height > 0)
            {
                withResolution = this.addParameter(withLocalTime, "res", this.width + "x" + this.height);
            }
            else
            {
                withResolution = withLocalTime;
            }
            String withCookieInfo = this.addParameter(withResolution, "cookie", this.requestCookie != null);
            String withCustomData = this.addParameter(withCookieInfo, "data", this.customData);
            String withCustomVar;
            //if (this.customVar.Count ==  0)
            {
                withCustomVar = withCustomData;
            }
            //else
            //{
            //    foreach (var item in this.customVar)
            //    {
            //        var list = new List<String>();
            //        list.Add(item.Key);
            //        list.Add(item.Value);
            //    }
            //    //withCustomVar = this.addParameter(withCustomData, "_cvar", JSON of customVar);
            //}
            String withRand = this.addParameter(withCustomVar, "r", new Random().NextDouble().ToString(CultureInfo.InvariantCulture).Substring(2, 8));
            String withDebug = withRand + this.debug_append_url;
            return withDebug;
        }

        private Uri makeUri(String queryString)
        {
            string path = String.Format("{0}{1}{2}{3}", apiurl.Scheme, Uri.SchemeDelimiter, apiurl.Authority, apiurl.AbsolutePath);
            return new Uri(this.apiurl, path+ "?" + queryString);
        }

        public class PiwikException : Exception
        {
            public PiwikException(string message, Exception inner)
                : base(message, inner)
            {
            }

            public PiwikException(string message)
                : base(message)
            {
            }
        }

        private String addParameter(String rootQuery, String name, int value)
        {
            return this.addParameter(rootQuery, name, value.ToString(CultureInfo.InvariantCulture), true);
        }

        private String addParameter(String rootQuery, String name, Uri value)
        {
            return this.addParameter(rootQuery, name, value == null ? null : value.AbsoluteUri.ToString(), true);
        }

        private String addParameter(String rootQuery, String name, DateTimeOffset? value)
        {
            return this.addParameter(rootQuery, name, (value ?? DateTimeOffset.UtcNow).ToString("r"), true);
        }

        private String addParameter(String rootQuery, String name, bool selection)
        {
            return this.addParameter(rootQuery, name, selection.ToString(), true);
        }

        /**
     * See the equivalent function. Will call this function with ignoreNull set 
     * to be <code>true</code>.
     * 
     * @param rootQuery the root query the new parameter will be added as string object
     * @param name the name of the parameter as string object
     * @param value the value ot the parameter as string object
     * @return the new query as a result of the root query with the new parameter 
     * and the value
     */

        private String addParameter(String rootQuery, String name, String value)
        {
            return this.addParameter(rootQuery, name, value, true);
        }

        /**
     * Adds a parameter to a given query and returns the full query.
     * If the given value is <code>null</code> the added query will be the string
     * representation of <code>null</code> and NOT the empty string.
     * If the given name is <code>null</code>, the value will be added as a 
     * single parameter.
     * Only if both name and value are <code>null</code> the function will
     * return the root query unmodified.
     * 
     * @param rootQuery the root query the new parameter will be added as string object
     * @param name the name of the parameter as string object
     * @param value the value ot the parameter as string object
     * @param ignoreNull <code>true</code> the hole parameter will be ignored if the value is <code>null</code>
     * @return the new query as a result of the root query with the new parameter 
     * and the value
     */

        private String addParameter(String rootQuery, String name, String value, bool ignoreNull)
        {
            String output;
            if ((name == null && value == null && rootQuery != null && !(rootQuery.Trim().Length > 0)) ||
                (value == null && ignoreNull))
            {
                output = rootQuery;
            }
            else if (name != null && rootQuery != null && !(rootQuery.Trim().Length > 0))
            {
                output = rootQuery + "&" + name + "=" + this.urlencode(value);
            }
            else if (rootQuery != null && !(rootQuery.Trim().Length > 0))
            {
                output = rootQuery + "&" + this.urlencode(value);
            }
            else if (name != null)
            {
                output = name + "=" + this.urlencode(value);
            }
            else
            {
                output = this.urlencode(value);
            }
            return output;
        }

        private String urlencode(String input)
        {
            return HttpUtility.UrlEncode(input);
        }

        /**
     * Creates an MD5 hash for the given input.
     * 
     * @param input the input string
     * @return the hashed string 
     */

        private String md5(String input)
        {
            MD5 m = MD5.Create();
            byte[] hash = m.ComputeHash(System.Text.Encoding.ASCII.GetBytes("23"));
            return BitConverter.ToString(hash);
        }

        public Uri getGoalTrackUri(String goal)
        {
            Uri output = null;
            try
            {
                String globalQuery = this.getGeneralQuery();
                String resultQuery = this.addParameter(globalQuery, "idgoal", goal);
                output = this.makeUri(resultQuery);
            }
            catch (UriFormatException e)
            {
                SimplePiwikTracker.LOG.error("Error while building track url", e);
            }
            return output;
        }

        public static class LOG
        {
            static LOG()
            {
                error = (s, exception) => { };
            }

            public static Action<string, Exception> error { get; set; }
        }


        public Uri getGoalTrackUri(String goal, String revenue)
        {
            Uri output = null;
            try
            {
                String globalQuery = this.getGeneralQuery();
                String qoalQuery = this.addParameter(globalQuery, "idgoal", goal);
                String resultQuery = this.addParameter(qoalQuery, "revenue", revenue);
                output = this.makeUri(resultQuery);
            }
            catch (UriFormatException e)
            {
                SimplePiwikTracker.LOG.error("Error while building track url", e);
            }
            return output;
        }

        public Uri getDownloadTackUri(String downloadurl)
        {
            Uri output = null;
            try
            {
                String globalQuery = this.getGeneralQuery();
                String resultQuery = this.addParameter(globalQuery, "download", downloadurl);
                output = this.makeUri(resultQuery);
            }
            catch (UriFormatException e)
            {
                SimplePiwikTracker.LOG.error("Error while building track url", e);
            }
            return output;
        }

        public Uri getLinkTackUri(String linkurl)
        {
            Uri output = null;
            try
            {
                String globalQuery = this.getGeneralQuery();
                String resultQuery = this.addParameter(globalQuery, "link", linkurl);
                output = this.makeUri(resultQuery);
            }
            catch (UriFormatException e)
            {
                SimplePiwikTracker.LOG.error("Error while building track url", e);
            }
            return output;
        }

        public Uri getPageTrackUri(String pagename)
        {
            Uri output = null;
            try
            {
                String globalQuery = this.getGeneralQuery();
                String resultQuery = this.addParameter(globalQuery, "action_name", pagename);
                output = this.makeUri(resultQuery);
            }
            catch (UriFormatException e)
            {
                SimplePiwikTracker.LOG.error("Error while building track url", e);
            }
            return output;
        }

        public void sendRequest(Uri destination)
        {
            if (destination != null)
            {
                try
                {
                    var connection = (HttpWebRequest) HttpWebRequest.Create(destination);
                    {

                        connection.AllowAutoRedirect = (false);
                        connection.Timeout = 600;
                        connection.UserAgent = userAgent;
                        
                        connection.Headers["Accept-Language"] = language;
                        if (requestCookie != null)
                        {
                            connection.CookieContainer.Add(requestCookie);
                        }
                        using (var responseData = (HttpWebResponse) connection.GetResponse())
                        {
                            if (responseData.Cookies.Count > 0)
                            {
                                var lastCookie = responseData.Cookies[responseData.Cookies.Count - 1];
                                if (lastCookie.Name.LastIndexOf("XDEBUG") == -1 &&
                                    lastCookie.Value.LastIndexOf("XDEBUG") == -1)
                                {
                                    requestCookie = lastCookie;
                                }
                            }
                        }
                    }

                }
                catch (IOException e)
                {
                    throw new PiwikException("Error while sending request to piwik", e);
                }
            }
        }
    }
}
