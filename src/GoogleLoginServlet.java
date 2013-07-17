import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.*;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLEncoder;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

@WebServlet("/google_login")
public class GoogleLoginServlet extends HttpServlet {

    private static final String LOGIN_URL = "https://accounts.google.com/o/oauth2/auth?";
    private static final String TOKEN_URL = "https://accounts.google.com/o/oauth2/token";
    private static final String TOKEN_INFO_URL = "https://www.googleapis.com/oauth2/v1/tokeninfo?";
    private static final String CLIENT_ID = "145631744627-c6le22tp15fh6sesd4a9ru4kadiis9oo.apps.googleusercontent.com";
    private static final String CLIENT_SECRET = "-yHzr71gU-TK_eSwnt8tK0Rn";
    private static final String REDIRECT_URI = "http://localhost:8080/google_auth_war_exploded/google_login";

    public GoogleLoginServlet() {
        super();
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String returnedState = req.getParameter("state");
        if (returnedState == null) {
            resp.getWriter().println("Can't access this page");
            return;
        }
        String storedState = (String) req.getSession().getAttribute("state");
        if (!returnedState.equals(storedState)) {
            resp.getWriter().println("Bad response");
            return;
        }

        // http://www.vogella.com/articles/ApacheHttpClient/article.html
        HttpClient client = new DefaultHttpClient();
        HttpPost post = new HttpPost(TOKEN_URL);
        try {
            List<NameValuePair> nvPairs = new ArrayList<NameValuePair>();
            nvPairs.add(new BasicNameValuePair("code", req.getParameter("code")));
            nvPairs.add(new BasicNameValuePair("client_id", CLIENT_ID));
            nvPairs.add(new BasicNameValuePair("client_secret", CLIENT_SECRET));
            nvPairs.add(new BasicNameValuePair("redirect_uri", REDIRECT_URI));
            nvPairs.add(new BasicNameValuePair("grant_type", "authorization_code"));
            post.setEntity(new UrlEncodedFormEntity(nvPairs));



            HttpResponse response = client.execute(post);
            BufferedReader br = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
            PrintWriter pageWriter = resp.getWriter();
            String tokenJSON = "";
            while (true) {
                String line = br.readLine();
                if (line == null) break;
                tokenJSON += line;
            }
            br.close();
            pageWriter.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        StringBuilder sb = new StringBuilder(TOKEN_INFO_URL);
        addQueryParameter(sb, "id_token", "");

        HttpGet get = new HttpGet();
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        HttpSession session = req.getSession();
        String securityToken = new BigInteger(130, new SecureRandom()).toString(32); // token to prevent forgery
        String currentURL = getFullURL(req);
        String state = String.format("security_token=%s&url=%s", securityToken, currentURL);
        session.setAttribute("state", state);

        StringBuilder sb = new StringBuilder(LOGIN_URL);
        addQueryParameter(sb, "client_id", CLIENT_ID);
        addQueryParameter(sb, "response_type", "code");
        addQueryParameter(sb, "scope", "openid%20email");
        addQueryParameter(sb, "state", URLEncoder.encode(state, "UTF-8"));
        addQueryParameter(sb, "redirect_uri", REDIRECT_URI);

        resp.sendRedirect(sb.toString());
    }

    private void addQueryParameter(StringBuilder sb, String key, String value) {
        sb.append(key);
        sb.append('=');
        sb.append(value);
        sb.append('&');
    }

    // http://www.jguru.com/faq/view.jsp?EID=35175
    private String getFullURL(HttpServletRequest req) {
        String file = req.getRequestURI();
        if (req.getQueryString() != null) {
            file += '?' + req.getQueryString();
        }
        try {
            URL url = new URL(req.getScheme(), req.getServerName(), req.getServerPort(), file);
            return url.toString();
        } catch (Exception e) {
            return "http://www.comprehend.com";
        }
    }
}
