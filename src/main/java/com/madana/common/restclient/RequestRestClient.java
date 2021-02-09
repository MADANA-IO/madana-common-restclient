package com.madana.common.restclient;

import java.io.IOException;
import java.io.StringWriter;
import java.util.List;

import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Feature;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.glassfish.jersey.client.oauth2.OAuth2ClientSupport;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.madana.common.datastructures.MDN_Certificate;
import com.madana.common.datastructures.MDN_Data;
import com.madana.common.datastructures.MDN_Token;
import com.madana.common.datastructures.MDN_UserCredentials;
import com.madana.common.datastructures.SignedData;
import com.madana.common.datastructures.node.NodeInfo;
import com.madana.common.datastructures.requests.Analysis;
import com.madana.common.datastructures.requests.AnalysisPreview;
import com.madana.common.datastructures.requests.AnalysisRequestAction;
import com.madana.common.datastructures.requests.AnalysisResult;
import com.madana.common.datastructures.requests.DataCollectionMethod;
import com.madana.common.datastructures.requests.DataCollectionType;
import com.madana.common.datastructures.requests.SystemRequestStatistics;
import com.madana.common.security.HashHandler;
import com.madana.common.security.crypto.AsymmetricCryptography;

public class RequestRestClient extends MDN_RestClient 
{

	public RequestRestClient(String string)
	{
		super(string);	// TODO Auto-generated constructor stub
	}
	public RequestRestClient() 
	{
		super();
	}
	/**
	 * Logon.
	 *
	 * @param strUserName the str user name
	 * @param strPassword the str password
	 * @return true, if successful
	 * @throws Exception the exception
	 */
	public boolean logon(String strUserName, String strPassword, String clientIPAddress) throws Exception
	{
		MDN_UserCredentials oCredentials = new MDN_UserCredentials();
		oCredentials.setPassword(strPassword);
		oCredentials.setUsername(strUserName);
		registerToken(oCredentials,clientIPAddress);
		return true;
	}
	/**
	 * Register token.
	 *
	 * @param oCredentials the o credentials
	 * @return the string
	 * @throws Exception the exception
	 */
	protected String registerToken(MDN_UserCredentials oCredentials, String clientIPAddress ) throws Exception
	{
		Response oResponse = client.target(MDN_RestClient.REST_URI).path("authentication").queryParam("clientIPAddress", clientIPAddress).request(MediaType.APPLICATION_JSON).post(Entity.entity(oCredentials, MediaType.APPLICATION_JSON)); 
		checkForError(oResponse, Response.Status.OK.getStatusCode() );
		MDN_Token oToken = oResponse.readEntity(MDN_Token.class);
		Feature feature = OAuth2ClientSupport.feature(oToken.getToken());
		client = ClientBuilder.newClient();
		client.register(feature);

		return oToken.getToken();
	}
	public String createAnalysisRequests(SignedData data)
	{
		Response oResponse = client.target(MDN_RestClient.REST_URI).path("requests").request(MediaType.APPLICATION_JSON).post(Entity.entity(data, MediaType.APPLICATION_JSON));
		String strResponse =  oResponse.readEntity(String.class);
		return strResponse;
	}
	public Analysis getRequest(String uuid)
	{

		Analysis oRequest = null;
		ObjectMapper mapper = new ObjectMapper();
		mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

		//Jackson's use of generics here are completely unsafe, but that's another issue
		try {
			JsonNode oJSON =client.target(MDN_RestClient.REST_URI).path("requests").path(uuid).request(MediaType.APPLICATION_JSON).get(JsonNode.class);
			oRequest = mapper.readValue(mapper.treeAsTokens(oJSON),   Analysis.class);


		} catch (JsonParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (JsonMappingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return oRequest;

	}
	public List<AnalysisRequestAction> getLastActions()
	{
		List<AnalysisRequestAction> actions = null;
		ObjectMapper mapper = new ObjectMapper();
		mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

		//Jackson's use of generics here are completely unsafe, but that's another issue
		try {
			JsonNode oJSON =client.target(MDN_RestClient.REST_URI).path("requests").path("actions").request(MediaType.APPLICATION_JSON).get(JsonNode.class);
			actions = mapper.readValue(mapper.treeAsTokens(oJSON),   new TypeReference<List<AnalysisRequestAction>>(){});


		} catch (JsonParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (JsonMappingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return actions;
	}
	public List<String> getAllAnalysisRequests()
	{
		List<String> oUUIDs = client.target(MDN_RestClient.REST_URI).path("requests").queryParam("new", "false").request(MediaType.APPLICATION_JSON).get(List.class);
		return oUUIDs;
	}
	public List<String> getAnalysisRequests(int offset, int limit)
	{
		List<String> oUUIDs = client.target(MDN_RestClient.REST_URI).path("requests").queryParam("new", "false").queryParam("offset", String.valueOf(offset)).queryParam("limit", String.valueOf(limit)).request(MediaType.APPLICATION_JSON).get(List.class);
		return oUUIDs;
	}
	public List<AnalysisPreview> getAnalysisRequestsWithPreview(int offset, int limit)
	{
		List<AnalysisPreview> actions = null;
		ObjectMapper mapper = new ObjectMapper();
		mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

		//Jackson's use of generics here are completely unsafe, but that's another issue
		try {
			JsonNode oJSON = client.target(MDN_RestClient.REST_URI).path("requests").queryParam("preview", "true").queryParam("new", "false").queryParam("offset", String.valueOf(offset)).queryParam("limit", String.valueOf(limit)).request(MediaType.APPLICATION_JSON).get(JsonNode.class);

			actions = mapper.readValue(mapper.treeAsTokens(oJSON),   new TypeReference<List<AnalysisPreview>>(){});


		} catch (JsonParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (JsonMappingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return actions;
	}
	public List<String> getProcessableRequests()
	{
		List<String> oUUIDs = client.target(MDN_RestClient.REST_URI).path("requests").queryParam("ready", "true").request(MediaType.APPLICATION_JSON).get(List.class);
		return oUUIDs;
	}
	public List<String> getNewAnalysisRequests()
	{
		List<String> oUUIDs = client.target(MDN_RestClient.REST_URI).path("requests").queryParam("new", "true").request(MediaType.APPLICATION_JSON).get(List.class);
		return oUUIDs;
	}
	public List<AnalysisPreview> getNewAnalysisRequestsWithPreview()
	{
		List<AnalysisPreview> actions = null;
		ObjectMapper mapper = new ObjectMapper();
		mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

		//Jackson's use of generics here are completely unsafe, but that's another issue
		try {
			JsonNode oJSON =client.target(MDN_RestClient.REST_URI).path("requests").queryParam("preview", "true").queryParam("new", "true").request(MediaType.APPLICATION_JSON).get(JsonNode.class);
			actions = mapper.readValue(mapper.treeAsTokens(oJSON),   new TypeReference<List<AnalysisPreview>>(){});


		} catch (JsonParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (JsonMappingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return actions;

	}
	public List<String> getMyAnalysisRequests()
	{
		List<String> oUUIDs = client.target(MDN_RestClient.REST_URI).path("requests").queryParam("created", "true").queryParam("created", "false").request(MediaType.APPLICATION_JSON).get(List.class);
		return oUUIDs;
	}
	public List<AnalysisRequestAction> getAllAnalysisRequestsHistory() {
		List<AnalysisRequestAction> actions = null;
		ObjectMapper mapper = new ObjectMapper();
		mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

		//Jackson's use of generics here are completely unsafe, but that's another issue
		try {
			JsonNode oJSON =client.target(MDN_RestClient.REST_URI).path("requests").queryParam("new", "false").queryParam("history", "true").request(MediaType.APPLICATION_JSON).get(JsonNode.class);
			actions = mapper.readValue(mapper.treeAsTokens(oJSON),   new TypeReference<List<AnalysisRequestAction>>(){});


		} catch (JsonParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (JsonMappingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return actions;

	}
	public void addDataToAnalysisRequest(String ruid, String data , 	AsymmetricCryptography asym) throws Exception
	{
		SignedData oData = new SignedData();
		oData.setData(data);
		oData.setSignature(hashAndSignData(data,asym));
		Response oResponse = client.target(MDN_RestClient.REST_URI).path("requests").path(ruid).path("data").request(MediaType.APPLICATION_JSON).post(Entity.entity(oData, MediaType.APPLICATION_JSON));
		checkForError(oResponse, Response.Status.OK.getStatusCode());
	}
	public void addDataToAnalysisRequest(String ruid, SignedData data ) throws Exception
	{
		

		Response oResponse = client.target(MDN_RestClient.REST_URI).path("requests").path(ruid).path("data").request(MediaType.APPLICATION_JSON).post(Entity.entity(data, MediaType.APPLICATION_JSON));
		checkForError(oResponse, Response.Status.OK.getStatusCode());
	}
	public List<SignedData> getDataFromAnalysisRequest(String ruid) throws Exception
	{
		List<SignedData> data = null;
		ObjectMapper mapper = new ObjectMapper();
		mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

		try {
			JsonNode oJSON =client.target(MDN_RestClient.REST_URI).path("requests").path(ruid).path("data").request(MediaType.APPLICATION_JSON).get(JsonNode.class);
			data = mapper.readValue(mapper.treeAsTokens(oJSON),   new TypeReference<List<SignedData>>(){});


		} catch (JsonParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (JsonMappingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return data;
	}

	public void agreeOnAnalysisRequest(String ruid) throws Exception
	{
		Response oResponse = client.target(MDN_RestClient.REST_URI).path("requests").path(ruid).path("consent").request(MediaType.APPLICATION_JSON).post(Entity.entity(null, MediaType.APPLICATION_JSON));
		checkForError(oResponse, Response.Status.OK.getStatusCode());
	}

	public void addResultToAnalysisRequest(String ruid, SignedData data) throws Exception
	{
		Response oResponse = client.target(MDN_RestClient.REST_URI).path("requests").path(ruid).path("result").request(MediaType.APPLICATION_JSON).post(Entity.entity(data, MediaType.APPLICATION_JSON));
		checkForError(oResponse, Response.Status.OK.getStatusCode());
	}
	public void cancelAnalysisRequest(String ruid, SignedData data) throws Exception
	{
		Response oResponse = client.target(MDN_RestClient.REST_URI).path("requests").path(ruid).path("cancel").request(MediaType.APPLICATION_JSON).post(Entity.entity(data, MediaType.APPLICATION_JSON));
		checkForError(oResponse, Response.Status.OK.getStatusCode());
	}
	public SystemRequestStatistics getRequestStats() {
		return client.target(MDN_RestClient.REST_URI).path("requests").path("stats")
				.request(MediaType.APPLICATION_JSON).get(SystemRequestStatistics.class);
	}


	public MDN_Certificate sendCertificateSigningRequest(PKCS10CertificationRequest csr) throws Exception
	{
		MDN_Data oData = new MDN_Data();
		oData.setData(certificationRequestToPEM(csr));

		Response oResponse = client.target(MDN_RestClient.REST_URI).path("certificates").request(MediaType.APPLICATION_JSON).post(Entity.entity(oData, MediaType.APPLICATION_JSON));
		checkForError(oResponse, Response.Status.OK.getStatusCode());	
		MDN_Certificate cert  = oResponse.readEntity(MDN_Certificate.class);
		return cert;
	}
	/**
	 * certificationRequestToPEM - Convert a PKCS10CertificationRequest to PEM
	 * format.
	 *
	 * @param csr The Certificate to convert
	 * @return An equivalent PEM format certificate.
	 * @throws IOException
	 */

	private String certificationRequestToPEM(PKCS10CertificationRequest csr) throws IOException {

		PemObject pemObject = new PemObject("CERTIFICATE REQUEST", csr.getEncoded());
		StringWriter strWriter;
		try (JcaPEMWriter pemWriter = new JcaPEMWriter(strWriter = new StringWriter())) {
			pemWriter.writeObject(pemObject);
		}
		return strWriter.toString();
	}
	static String hashAndSignData(String data, 	AsymmetricCryptography asym ) throws Exception
	{
		String hash=HashHandler.generateHash(data);
		System.out.println("...		Hash of "+data+" "+hash);

		String signature =asym.sign(hash);
		System.out.println("...		Signature of "+data+" "+signature);
		return signature;
	}
	public AnalysisResult getAnalysisResult(String ruid) throws Exception
	{

		AnalysisResult data = null;
		ObjectMapper mapper = new ObjectMapper();
		mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

		try 
		{
			JsonNode oJSON =client.target(MDN_RestClient.REST_URI).path("requests").path(ruid).path("result").request(MediaType.APPLICATION_JSON).get(JsonNode.class);
			data = mapper.readValue(mapper.treeAsTokens(oJSON),   AnalysisResult.class);

		} catch (JsonParseException e) 
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (JsonMappingException e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) 
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return data;
	}
	public void assignAgent(String ruid) 
	{
		Response oResponse = client.target(MDN_RestClient.REST_URI).path("requests").path(ruid).path("agent").request(MediaType.APPLICATION_JSON).post(Entity.entity(null, MediaType.APPLICATION_JSON));


	}
	public void publishNodeDescriptor(NodeInfo info) throws Exception 
	{
		Response oResponse = client.target(MDN_RestClient.REST_URI).path("nodes").request(MediaType.APPLICATION_JSON).post(Entity.entity(info, MediaType.APPLICATION_JSON));
		checkForError(oResponse, Response.Status.OK.getStatusCode());
	}

	public List<NodeInfo> getNodes()
	{
		List<NodeInfo> nodes = null;
		ObjectMapper mapper = new ObjectMapper();
		mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

		//Jackson's use of generics here are completely unsafe, but that's another issue
		try {
			JsonNode oJSON =client.target(MDN_RestClient.REST_URI).path("nodes").request(MediaType.APPLICATION_JSON).get(JsonNode.class);
			nodes = mapper.readValue(mapper.treeAsTokens(oJSON),   new TypeReference<List<NodeInfo>>(){});


		} catch (JsonParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (JsonMappingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return nodes;
	}
	public List<NodeInfo> getNodesOwnedBy(String username)
	{
		List<NodeInfo> nodes = null;
		ObjectMapper mapper = new ObjectMapper();
		mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

		//Jackson's use of generics here are completely unsafe, but that's another issue
		try {
			JsonNode oJSON =client.target(MDN_RestClient.REST_URI).path("nodes").queryParam("username", username).request(MediaType.APPLICATION_JSON).get(JsonNode.class);
			nodes = mapper.readValue(mapper.treeAsTokens(oJSON),   new TypeReference<List<NodeInfo>>(){});


		} catch (JsonParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (JsonMappingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return nodes;
	}
	public MDN_Certificate getRootCertificate()
	{
		MDN_Certificate cert = null;
		ObjectMapper mapper = new ObjectMapper();
		mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

		//Jackson's use of generics here are completely unsafe, but that's another issue
		try {
			JsonNode oJSON =client.target(MDN_RestClient.REST_URI).path("certificates").path("root").request(MediaType.APPLICATION_JSON).get(JsonNode.class);
			cert = mapper.readValue(mapper.treeAsTokens(oJSON),   MDN_Certificate.class);


		} catch (JsonParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (JsonMappingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return cert;
	}
	public MDN_Certificate getCertificate(String fingerprint)
	{
		MDN_Certificate cert = null;
		ObjectMapper mapper = new ObjectMapper();
		mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

		//Jackson's use of generics here are completely unsafe, but that's another issue
		try {
			JsonNode oJSON =client.target(MDN_RestClient.REST_URI).path("certificates").path(fingerprint).request(MediaType.APPLICATION_JSON).get(JsonNode.class);
			cert = mapper.readValue(mapper.treeAsTokens(oJSON),   MDN_Certificate.class);


		} catch (JsonParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (JsonMappingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return cert;
	}
	public List<DataCollectionType> getDataCollectionTypess()
	{
		List<DataCollectionType> nodes = null;
		ObjectMapper mapper = new ObjectMapper();
		mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

		//Jackson's use of generics here are completely unsafe, but that's another issue
		try {
			JsonNode oJSON =client.target(MDN_RestClient.REST_URI).path("datacollection").path("types").request(MediaType.APPLICATION_JSON).get(JsonNode.class);
			nodes = mapper.readValue(mapper.treeAsTokens(oJSON),   new TypeReference<List<DataCollectionType>>(){});


		} catch (JsonParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (JsonMappingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return nodes;
	}
	public List<DataCollectionMethod> getDataCollectionMethods()
	{
		List<DataCollectionMethod> nodes = null;
		ObjectMapper mapper = new ObjectMapper();
		mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

		//Jackson's use of generics here are completely unsafe, but that's another issue
		try {
			JsonNode oJSON =client.target(MDN_RestClient.REST_URI).path("datacollection").path("methods").request(MediaType.APPLICATION_JSON).get(JsonNode.class);
			nodes = mapper.readValue(mapper.treeAsTokens(oJSON),   new TypeReference<List<DataCollectionMethod>>(){});


		} catch (JsonParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (JsonMappingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return nodes;
	}
	public List<DataCollectionMethod> getDataCollectionMethodsByType(String typeName)  throws Exception
	{
		List<DataCollectionMethod> nodes = null;
		ObjectMapper mapper = new ObjectMapper();
		mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

		//Jackson's use of generics here are completely unsafe, but that's another issue
		try {
			JsonNode oJSON =client.target(MDN_RestClient.REST_URI).path("datacollection").path("types").path(typeName).path("methods").request(MediaType.APPLICATION_JSON).get(JsonNode.class);
			nodes = mapper.readValue(mapper.treeAsTokens(oJSON),   new TypeReference<List<DataCollectionMethod>>(){});


		} catch (JsonParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (JsonMappingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return nodes;
	}
	
}
