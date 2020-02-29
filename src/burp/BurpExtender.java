package burp;

/*
 * Cartogradur is designed to uncover Mapping API keys that are improperly configured mapping APIs
 * 
 * Author: Jonathan "Security Chops" Crosby
 * Website: https://securitychops.com/
 * Version: 1.0.0.0
 * */

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.net.URL;
import java.net.URLConnection;

public class BurpExtender implements IBurpExtender, IScannerCheck
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private final String name;

    public BurpExtender()
    {
        this.name = "Cartogradur";
    }

    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        
        callbacks.setExtensionName(this.name);
        callbacks.registerScannerCheck(this);
    }

    public IBurpExtenderCallbacks getCallbacks()
    {
        return this.callbacks;
    }
    
    public Boolean is_api_key_vulnerable(String in_url, String vulnerable_text)
    {
    	try
    	{
        	URL url = new URL(in_url);
        	URLConnection conn = url.openConnection();
        	
        	BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        	
            String inputLine;
            while ((inputLine = reader.readLine()) != null)
            {
                if(inputLine.contains(vulnerable_text))
                {
                	reader.close();
                	return true;
                }
            }
            return false;
    	}
    	catch(Exception e) 
    	{
    		//Not the end of the world ... carry on my wayward plug-in
    	}
    	
    	return false;
    }
    
    // search body for google maps api key
    // if found make active request to google to see if
    // it is vulnerable to api misuse
    public ArrayList<String> get_google_api_issues(String body, URL request_url)
    {
    	//new list of scan issues to report
    	ArrayList<String> return_me = new ArrayList<String>();	
    	
    	try
    	{    		
        	//quick check if this is the request going to google, as if so we don't care
        	String request_host = request_url.getHost();
        	if(request_host.contains("maps.googleapis.com"))
        	{
        		return return_me;
        	}    		
    		
    		final String google_maps_geocode_url = "https://maps.googleapis.com/maps/api/geocode/json?address=1600+Amphitheatre+Parkway,+Mountain+View,+CA&key=";
	    	final Pattern google_maps_api_pattern = Pattern.compile("AIza[0-9A-Za-z-_]{35}");
	    	
	    	Matcher google_maps_api_keys = google_maps_api_pattern.matcher(body);
	    	
	    	ArrayList<String> unique_api_keys = new ArrayList<String>();
	    	while(google_maps_api_keys.find())
	    	{
	    		String tmp_matched_key = google_maps_api_keys.group();
	    		
	    		if(!unique_api_keys.contains(tmp_matched_key))
	    		{
	    			unique_api_keys.add(tmp_matched_key);
	    		}
	    	}
	    	
	    	for (String api_key : unique_api_keys)
	    	{
	    	  	String final_vuln_url = google_maps_geocode_url + api_key;
	    	  	
	    		String final_vuln_text = "1600";	    	
	    		
	    		Boolean is_vulnerable = is_api_key_vulnerable(final_vuln_url, final_vuln_text);
	    		
	    		if (is_vulnerable)
	    		{
	    			return_me.add(api_key);
	    		}
	    	}
	    	
    	}
    	catch(Exception e) 
    	{
    		//Not the end of the world ... carry on my wayward plug-in
    	}
    	
    	//return any issues discovered
		return return_me;    	
    }
    
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse requestResponse)
    {
    	//new list of scan issues to report
    	List<IScanIssue> issues = new ArrayList<IScanIssue>();
    	
    	//byte array of the response of our request
    	byte[] response_bytes = requestResponse.getResponse();
    	
    	//info about our response
    	IResponseInfo response_info = helpers.analyzeResponse(response_bytes);
    	
    	//httpservice from our request
    	IHttpService http_service = requestResponse.getHttpService();
    	
    	// get URL of request
    	URL request_url = helpers.analyzeRequest(requestResponse).getUrl();
    	
    	//get the offset of where the body starts
    	int body_offset = response_info.getBodyOffset();
    	
    	//extracting just the body from the response
    	byte[] response_body = Arrays.copyOfRange(response_bytes, body_offset, response_bytes.length);
    	
    	//getting string version of the body for usage in our API checks
    	String clean_body = helpers.bytesToString(response_body);

    	ArrayList<String> google_issues = get_google_api_issues(clean_body, request_url);
    	
    	for(String google_issue : google_issues)
    	{			
    		issues.add(new CustomScanIssue(
    							http_service,
			    			    request_url,
			    			    new IHttpRequestResponse[] {},
			    			    "Google Maps API Issue",
			    			    "The response contains the following vulnerable geo location Google Maps API key: " + google_issue + "\n",
			    			    "High")
    				);
    	}
    	
    	return issues;
    }
    
	public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) 
	{
	    return null;
	}
    
	public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) 
	{
	    if( existingIssue.getIssueDetail().equals(newIssue.getIssueDetail()) ) {
	      return -1;
	    }
	    else {
	      return 0;
	    }
	}
}

//
// class implementing IScanIssue to hold our custom scan issue details
// https://github.com/PortSwigger/example-scanner-checks/blob/master/java/BurpExtender.java
//
class CustomScanIssue implements IScanIssue
{
	 private IHttpService httpService;
	 private URL url;
	 private IHttpRequestResponse[] httpMessages;
	 private String name;
	 private String detail;
	 private String severity;

	 public CustomScanIssue(
	         IHttpService httpService,
	         URL url, 
	         IHttpRequestResponse[] httpMessages, 
	         String name,
	         String detail,
	         String severity)
	 {
	     this.httpService = httpService;
	     this.url = url;
	     this.httpMessages = httpMessages;
	     this.name = name;
	     this.detail = detail;
	     this.severity = severity;
	 }
 
	 @Override
	 public URL getUrl()
	 {
	     return url;
	 }
	
	 @Override
	 public String getIssueName()
	 {
	     return name;
	 }
	
	 @Override
	 public int getIssueType()
	 {
	     return 0;
	 }
	
	 @Override
	 public String getSeverity()
	 {
	     return severity;
	 }
	
	 @Override
	 public String getConfidence()
	 {
	     return "Certain";
	 }
	
	 @Override
	 public String getIssueBackground()
	 {
	     return null;
	 }
	
	 @Override
	 public String getRemediationBackground()
	 {
	     return null;
	 }
	
	 @Override
	 public String getIssueDetail()
	 {
	     return detail;
	 }
	
	 @Override
	 public String getRemediationDetail()
	 {
	     return null;
	 }
	
	 @Override
	 public IHttpRequestResponse[] getHttpMessages()
	 {
	     return httpMessages;
	 }
	
	 @Override
	 public IHttpService getHttpService()
	 {
	     return httpService;
	 }
}
