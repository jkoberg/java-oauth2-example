import java.io.IOException;

import org.apache.oltu.oauth2.client.response.OAuthResourceResponse;
import org.apache.oltu.oauth2.common.token.OAuthToken;
import org.json.JSONArray;
import org.json.JSONTokener;

/**
 * A sample OAuth2-using application that makes a request to the query endpoint on a VersionOne server
 * and parses the data returned.
 * 
 * @author JKoberg
 *
 */

public class App {
	public static void main(String[] args) throws Exception {
		String clientSecrets = "C:\\Users\\JKoberg\\support\\v1production_oauth\\client_secrets.json";
		String storedCredentials = "C:\\Users\\JKoberg\\support\\v1production_oauth\\stored_credentials.json";
		String scope = "query-api-1.0 apiv1";
		String queryUrl = "https://www7.v1host.com/V1Production/query.v1";
		String query = "{\"from\":\"Member\"}";
		
		OAuth2Client o = new OAuth2Client(clientSecrets, storedCredentials);
		
		OAuthToken creds;
		
		try {
			creds = o.ReadStoredCreds();
		}
		catch(IOException e) {
			String code = o.PromptUserForCode(scope);
			creds = o.TradeCodeForToken(code);
			o.WriteTokenToStoredCreds(creds);
		}
		
		OAuthResourceResponse httpResponse = o.PostHttp(creds, queryUrl, query);
		String body = httpResponse.getBody();
		JSONArray j = new JSONArray(new JSONTokener(body));
		System.out.println(j.toString());
	}
}
