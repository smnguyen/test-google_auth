import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLEncoder;
import java.security.SecureRandom;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@WebServlet("/google_login")
public class GoogleLoginServlet extends HttpServlet {

    private static final String LOGIN_URL = "https://accounts.google.com/o/oauth2/auth?";
    private static final String CLIENT_ID = "145631744627-c6le22tp15fh6sesd4a9ru4kadiis9oo.apps.googleusercontent.com";
    private static final String CLIENT_SECRET = "-yHzr71gU-TK_eSwnt8tK0Rn";

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

        String code = req.getParameter("code");

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
        addQueryParameter(sb, "redirect_uri", currentURL);

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
