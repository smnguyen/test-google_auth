import com.google.api.client.googleapis.auth.oauth2.*;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import org.apache.commons.codec.binary.Base64;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.*;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

@WebServlet("/google_login")
public class GoogleLoginServlet extends HttpServlet {

    private static final String CLIENT_ID = "145631744627-c6le22tp15fh6sesd4a9ru4kadiis9oo.apps.googleusercontent.com";
    private static final String CLIENT_SECRET = "-yHzr71gU-TK_eSwnt8tK0Rn";
    private static final String REDIRECT_URI = "http://localhost:8080/google_auth_war_exploded/google_login";

    private GsonFactory gf = new GsonFactory();
    private NetHttpTransport nht = new NetHttpTransport();
    private GoogleAuthorizationCodeTokenRequest tokenRequest;
    private GoogleIdTokenVerifier verifier;

    public GoogleLoginServlet() {
        super();
        verifier = new GoogleIdTokenVerifier.Builder(nht, gf).build();
        tokenRequest = new GoogleAuthorizationCodeTokenRequest(nht, gf, CLIENT_ID, CLIENT_SECRET, "", REDIRECT_URI);
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

        PrintWriter writer = resp.getWriter();
        String idToken = null;
        try {
            tokenRequest.setCode(req.getParameter("code"));
            GoogleTokenResponse token = tokenRequest.execute();
            idToken = token.getIdToken(); // .getIdToken() is in beta?
            GoogleIdToken gIDt = verifier.verify(idToken);
            if (gIDt == null) {
                writer.println("Invalid token");
                return;
            }
            writer.println("ID token: " + idToken + "\n");
            writer.println("Your email is " + gIDt.getPayload().getEmail());
            String verified = gIDt.getPayload().getEmailVerified() ? "" : "not ";
            writer.println("Your email has " + verified + "been verified" + "\n");   // bug on Google's end?
        } catch (GeneralSecurityException gse) {
            // ignore?
        } catch (IOException ioe) {
            writer.println(ioe);
            writer.println("Could not verify your identity");
            return;
        }

        // decoding the ID token manually
        String[] tokenParts = idToken.split("\\.");   // split on period
        byte[] decodedAlg = Base64.decodeBase64(tokenParts[0]);
        byte[] decodedUser = Base64.decodeBase64(tokenParts[1]);
        writer.println(new String(decodedUser, "UTF-8"));
        writer.println(new String(decodedAlg, "UTF-8"));

        /* more info: http://www.tbray.org/ongoing/When/201x/2013/04/04/ID-Tokens */
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        HttpSession session = req.getSession();
        String securityToken = new BigInteger(130, new SecureRandom()).toString(32); // token to prevent forgery
        String state = String.format("security_token=%s&url=%s", securityToken, REDIRECT_URI);
        session.setAttribute("state", state);

        GoogleAuthorizationCodeRequestUrl urlBuilder = new GoogleAuthorizationCodeRequestUrl(
                CLIENT_ID,
                REDIRECT_URI,
                Arrays.asList("openid", "email"))
                .setState(state)
                .setResponseTypes(Arrays.asList("code"));

        resp.sendRedirect(urlBuilder.build());
    }
}
