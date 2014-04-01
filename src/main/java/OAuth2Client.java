import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;

import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthBearerClientRequest;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAccessTokenResponse;
import org.apache.oltu.oauth2.client.response.OAuthJSONAccessTokenResponse;
import org.apache.oltu.oauth2.client.response.OAuthResourceResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.apache.oltu.oauth2.common.token.BasicOAuthToken;
import org.apache.oltu.oauth2.common.token.OAuthToken;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;


public class OAuth2Client {
	
	private String clientSecretsFile;
	private String storedCredsFile;
	private Options options;
	
	public OAuth2Client(String clientSecretsFile, String storedCredsFile) throws JSONException, IOException {
		this.clientSecretsFile = clientSecretsFile;
		this.storedCredsFile = storedCredsFile;
		this.options = ReadClientSecrets(clientSecretsFile);
	}
	
	public static OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
	
	public static class Options {
		public String ClientId;
		public String ClientSecret;
		public String TokenUrl;
		public String AuthUrl;
		public String RedirectUrl;
	}
	
	public Options ReadClientSecrets(String filename) throws JSONException, IOException {
		byte[] bytes = Files.readAllBytes(Paths.get(filename));
		JSONObject j = new JSONObject(new JSONTokener(new String(bytes, "UTF-8"))).getJSONObject("installed");
		Options o = new Options();
		o.ClientId = j.getString("client_id");
		o.ClientSecret = j.getString("client_secret");
		o.AuthUrl = j.getString("auth_uri");
		o.TokenUrl = j.getString("token_uri");
		o.RedirectUrl = j.getJSONArray("redirect_uris").getString(0);
		return o;
	}
			
	
    public String PromptUserForCode(String scope) throws OAuthSystemException, IOException {
        OAuthClientRequest request =
        	OAuthClientRequest
            	.authorizationLocation(options.AuthUrl)
            	.setClientId(options.ClientId)
            	.setRedirectURI(options.RedirectUrl)
            	.setScope(scope)
            	.setResponseType("code")
            	.buildQueryMessage();

        //in web application you make redirection to uri:
        System.out.println("Visit: " + request.getLocationUri() + "\nand grant permission");

        System.out.print("Now enter the OAuth code you have received at the redirect URI: ");
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        String code = br.readLine();
        return code;
    }
        

    public OAuthToken TradeCodeForToken(String code) throws OAuthSystemException, IOException, OAuthProblemException {
    	OAuthClientRequest request = OAuthClientRequest
            	.tokenLocation(options.TokenUrl)
                .setGrantType(GrantType.AUTHORIZATION_CODE)
                .setClientId(options.ClientId)
                .setClientSecret(options.ClientSecret)
                .setRedirectURI(options.RedirectUrl)
                .setCode(code)
                .buildBodyMessage();
            OAuthJSONAccessTokenResponse oAuthResponse = oAuthClient.accessToken(request);
            return oAuthResponse.getOAuthToken();
    }
    
    public OAuthToken WriteTokenToStoredCreds(OAuthToken token) throws UnsupportedEncodingException, IOException {
            // Write the access token to a stored_credentials.json file
            JSONObject j = new JSONObject();
            j.put("access_token", token.getAccessToken());
            j.put("refresh_token", token.getRefreshToken());
            j.put("token_type", "Bearer");
            j.put("scope", token.getScope());
            j.put("expires_in", token.getExpiresIn());
            String s = j.toString();
            
            Files.write(Paths.get(storedCredsFile), s.getBytes("UTF-8"));
            // Read the token from the stored_credentials.json file
            return token;
        }
    
    
    public OAuthResourceResponse TryHttp(OAuthToken creds, String path) throws OAuthSystemException, OAuthProblemException {
    	OAuthClientRequest bearerClientRequest =
    		new OAuthBearerClientRequest(path)
  	        	.setAccessToken(creds.getAccessToken())
  	        	.buildHeaderMessage();
    	OAuthResourceResponse resp =  oAuthClient.resource(bearerClientRequest, OAuth.HttpMethod.GET, OAuthResourceResponse.class);
    	return resp;
    }
    
    
    
    /**
     * Does an HTTP GET and implements the OAuth2 refresh logic.
     * @param options
     * @param creds
     * @param path
     * @return
     * @throws OAuthSystemException
     * @throws OAuthProblemException
     * @throws IOException 
     * @throws UnsupportedEncodingException 
     */
    public OAuthResourceResponse GetHttp(OAuthToken creds, String path) throws OAuthSystemException, OAuthProblemException, UnsupportedEncodingException, IOException {
    	OAuthResourceResponse resp = TryHttp(creds, path);
    	if(resp.getResponseCode() != 401) {
    		return resp;
    	} else {
    		OAuthClientRequest request = OAuthClientRequest
				.tokenLocation(options.TokenUrl)
				.setGrantType(GrantType.REFRESH_TOKEN)
				.setClientId(options.ClientId)
				.setClientSecret(options.ClientSecret)
				.setRedirectURI(options.RedirectUrl)
				.setRefreshToken(creds.getRefreshToken())
				.buildBodyMessage();
    		OAuthToken newCreds = oAuthClient.accessToken(request).getOAuthToken();
    		WriteTokenToStoredCreds(newCreds);
    		return TryHttp(newCreds, path);
    	}
	}
    	
    

	public OAuthToken ReadStoredCreds() throws IOException {
		byte[] bytes = Files.readAllBytes(Paths.get(storedCredsFile));
		JSONObject j = new JSONObject(new JSONTokener(new String(bytes, "UTF-8")));
		return new BasicOAuthToken(
				j.getString("access_token"),
				j.getLong("expires_in"),
				j.getString("refresh_token"),
				j.getString("scope")
				);
	}

	
	
	
}