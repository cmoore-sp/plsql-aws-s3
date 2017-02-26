create or replace package body aws4_s3_pkg 
as

-----------------------------------------------------------------------------------------
--
-- AWS Signature Version 4 - reference below
-- http://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html
-- Great help from
-- http://czak.pl/2015/09/15/s3-rest-api-with-curl.html
--
-- Purpose: The AWS authentication process has updated since the publication of the
-- original Alexandria Library tools.
--
-- In tribute of Morten Braten and Jason Straub, I have including their work with 
-- attributions and left their formatting in place.
--
-- Date: February 2017
-- Author: Christina Moore

-----------------------------------------------------------------------------------------

-- the following global settings will need to be changed for your environment
	
  g_aws_id                 	varchar2(20) := '#####YourID####'; -- AWS access key ID
  g_aws_key                	varchar2(40) := '#####YourSecretKey######'; -- AWS secret key
	g_wallet_path							constant varchar2(100) := 'file:d:\app\oracle\admin\orcl\wallet\';
	g_wallet_pwd							constant varchar2(100) := 'Wallet-Password';
  g_gmt_offset							number := 0; -- your timezone GMT adjustment
	g_aws_region							varchar2(40) := 'us-east-1';
	
	g_aws_service							varchar2(40) := 's3';

	-- this information appears within the XML data that returns. 
  g_aws_namespace_s3       	constant varchar2(255) := 'http://s3.amazonaws.com/doc/2006-03-01/';
  g_aws_namespace_s3_full  	constant varchar2(255) := 'xmlns="' || g_aws_namespace_s3 || '"';
	g_ISO8601_format					constant varchar2(30) := 'YYYYMMDD"T"HH24MISS"Z"';
	g_date_format_xml        	constant varchar2(30) := 'YYYY-MM-DD"T"HH24:MI:SS".000Z"';
	g_aws4_auth								constant varchar2(30) := 'AWS4-HMAC-SHA256';
	crlf											constant varchar2(2) 	:= chr(13) || chr(10);
	cr												constant varchar2(2)	:= chr(13);	
	lf												constant varchar2(1)	:= chr(10); -- USE THIS FOR NEW LINE!!!!
	amp												constant varchar2(1)	:= chr(38);	
	slsh											constant varchar2(3)	:= '%2F';	
	-- this is the SHA256 HASH of a empty string. It is used when the request is null
	g_null_hash								varchar2(100) := 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
	
-- Keys for testing with ŁUKASZ ADAMCZAK blog ( http://czak.pl/2015/09/15/s3-rest-api-with-curl.html)
-- Keys also work for testing with AWS page http://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
-- uncomment these if you want to run through his example to re-verify the hashing logic
--  g_aws_id                 	varchar2(20) := 'AKIAIOSFODNN7EXAMPLE'; -- AWS access key ID
--  g_aws_key                	varchar2(40) := 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'; -- AWS secret key

--------------------------------------------------------------------------------
-- 													S E C T I O N		
--
--					Private Functions and Procedures AWS4 Signature and HTTPS Request
--
--------------------------------------------------------------------------------
procedure validate_http_method (
	P_HTTP_METHOD 	in varchar2,
	P_PROCEDURE			in varchar2
	)
as
	------------------------------------------------------------------------------
	-- Function: 	Validate_HTTP_Method
	-- Author:		Christina Moore
	-- Date:			07FEB2017
	-- Version:		0.1
	--
	-- Confirms HTTP method - GET, POST
	--
	-- Revisions:
	--
	------------------------------------------------------------------------------
	l_valid			boolean := false;
begin
	case p_http_method
		when 'GET' then l_valid := true;
		when 'POST' then l_valid := true;
		when 'PUT' then l_valid := true;
		when 'DELETE' then l_valid := true;
		else l_valid := false;
	end case;
	if not l_valid then
		raise_application_error (-20000,
			'HTTP Method is not valid in aws4_s3_pkg.'||P_PROCEDURE);   
	end if;
end validate_http_method;

function aws4_sha256 (
	P_STRING			varchar2
	) return varchar2
as
	------------------------------------------------------------------------------
	-- Function: 	AWS4_sha256
	-- Author:		Christina Moore
	-- Date:			04FEB2017
	-- Version:		0.1
	--
	-- SHA256 hash on the string provided
	-- AWS requires that the hash is in lower case
	--
	-- Revisions:
	--
	------------------------------------------------------------------------------
	l_return									varchar2(2000);
	l_hash										raw(2000);
	l_source									raw(2000);
begin
	l_source		:= utl_i18n.string_to_raw(P_STRING,'AL32UTF8');
	l_hash 			:= dbms_crypto.hash(
									src => l_source,
									typ => dbms_crypto.hash_sh256
								);

	l_return := lower(rawtohex(l_hash));
	return l_return;
end aws4_sha256;

function aws4_sha256 (
	P_BLOB			in blob
	) return varchar2
as
	------------------------------------------------------------------------------
	-- Function: 	AWS4_sha256
	-- Author:		Christina Moore
	-- Date:			04FEB2017
	-- Version:		0.1
	--
	-- SHA256 hash on the blob provided
	-- AWS requires that the hash is in lower case
	--
	-- Revisions:
	--
	------------------------------------------------------------------------------
	l_return									varchar2(2000);
	l_hash										raw(2000);
	l_source									raw(2000);
	l_blob_amount       			integer := 2000;
	l_blob_buffer       			varchar2(4000);
	l_blob_pos          			integer := 1;
	
begin

	--l_source		:= utl_i18n.string_to_raw(P_STRING,'AL32UTF8');
	l_hash 			:= dbms_crypto.hash(
									src => P_BLOB,
									typ => dbms_crypto.hash_sh256
								);

	l_return := lower(rawtohex(l_hash));
	return l_return;
end aws4_sha256;

function aws4_signing_key (
	P_STRING_TO_SIGN		varchar2,
	P_DATE							date
	) return varchar2
	------------------------------------------------------------------------------
	-- Function: 	AWS4_SIGNING_KEY
	-- Author:		Christina Moore
	-- Date:			04FEB2017
	-- Version:		0.1
	--
	-- Parameters
	--	String-to-Sign	- the string to sign, see AWS documentation 
	--										and function signature string in this packages
	--	Date - current date
	--
	-- Follows the guidence of the AWS Signature Version 4 documentation
	-- http://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html
	-- In accordance with the documentation, the StringToSign is provided to the function
	-- The date is provided so that debugging against known standards is possible.
	-- 
	-- Note that the String to Sign is a complicated multi-line effort that starts with
	-- AWS-HMAC-SHA256
	-- This String to Sign is generated in Function ...
	--
	-- Revisions:
	--
	------------------------------------------------------------------------------
as
	l_return									varchar2(2000);
	l_date_string							varchar2(50);
	l_key_bytes_raw						raw(2000);
	l_source									raw(2000);
	l_date_key								raw(2000);
	l_date_region_key					raw(2000);
	l_date_region_service_key	raw(2000);
	l_signing_key							raw(2000);
	l_signature								raw(2000);
	l_date										date;
	
	-- notes on debugging
	-- 1. this calls the Alexandria DEBUG_PKG
	-- 2. You'll need to go into that package body and set m_debugging := true
	-- 3. You'll need to compile the Alexandria DEBUG_PKG Body
	-- 4. You'll then also need to turn the local debug option to true
	l_debug							boolean := false;
	
begin
	-- For testing in accordance with 
	--   http://czak.pl/2015/09/15/s3-rest-api-with-curl.html
	--   use 15 Sep 2015 12:45:00 GMT to get known results
	l_date_string := to_char(P_DATE, 'YYYYMMDD');

	-- per AWS documentation
	-- 2 Signing Key
	-- DateKey = HMAC-SHA256("AWS4" + "<SecretAccessKey>","<yyyymmdd>")
	l_key_bytes_raw := utl_i18n.string_to_raw('AWS4' || g_aws_key, 'AL32UTF8');
	l_source				:= utl_i18n.string_to_raw(l_date_string, 'AL32UTF8');
	l_date_key 			:= dbms_crypto.mac (
				src => l_source, 
				typ => dbms_crypto.hmac_sh256, 
				key => l_key_bytes_raw
				);

	-- DateRegionKey = HMAC-SHA256(DateKey,"<aws-region>")
	l_source					:= utl_i18n.string_to_raw(g_aws_region,'AL32UTF8');
	l_date_region_key := dbms_crypto.mac (
				src => l_source, 
				typ => dbms_crypto.hmac_sh256, 
				key => l_date_key
				);
	
	-- DateRegionServiceKey = HMAC-SHA256(DateRegionKey,"<aws-service>")
	l_source									:= utl_i18n.string_to_raw(g_aws_service,'AL32UTF8');
	l_date_region_service_key := dbms_crypto.mac (
				src => l_source, 
				typ => dbms_crypto.hmac_sh256, 
				key => l_date_region_key
			);

	-- SigningKey = HMAC-SHA256(DateRegionServiceKey, "aws4_request")
	l_source			:= utl_i18n.string_to_raw('aws4_request');
	l_signing_key := dbms_crypto.mac (
				src => l_source, 
				typ => dbms_crypto.hmac_sh256, 
				key => l_date_region_service_key
			);
	if l_debug then
		debug_pkg.print ('Signing Key', l_signing_key);
	end if;
	
	-- 3. Signature
	-- signature = hex(HMAC-SHA256(SigningKey, StringToSign))
	l_source		:= utl_i18n.string_to_raw(P_STRING_TO_SIGN);
	l_signature := dbms_crypto.mac (
				src => l_source, 
				typ => dbms_crypto.hmac_sh256, 
				key => l_signing_key
			);
	l_return := lower(rawtohex(l_signature));
	return l_return;
end aws4_signing_key;

function ISO_8601 (
		P_DATE		in timestamp,
		P_TIMEZONE	in varchar2 default 'UTC'
		) return varchar2
as
	------------------------------------------------------------------------------
	-- Function: 	ISO_8601
	-- Author:		Christina Moore
	-- Date:			04FEB2017
	-- Version:		0.1
	--
	-- Generates a varchar date in the ISO_8601 format. The function
	-- Also converts from the provided timezone to UTC/GMT. It does 
	-- assume with default that your work and server is on UTC.
	--
	-- Revisions:
	--
	------------------------------------------------------------------------------
	l_timestamp		timestamp;
	l_iso_8601		varchar2(60);
begin
	-- convert the date/time to UTC/Zulu/GMT
	select 
		cast(P_DATE as timestamp with time zone) at time zone 'UTC' 
		into
		l_timestamp
	from dual;
	-- convert the format to ISO_8601/JSON format
	if l_timestamp is not null then
		l_iso_8601 := to_char(l_timestamp, g_ISO8601_format);
	else
		l_iso_8601 := null;
	end if;
	return l_iso_8601;
end iso_8601;


function canonical_request (
	P_BUCKET						in varchar2,
	P_HTTP_METHOD				in varchar2,
	P_CANONICAL_URI			in varchar2,
	P_QUERY_STRING			in varchar2,
	P_DATE							in date,
	P_PAYLOAD_HASH			in varchar2,
	P_CANONICAL_REQUEST	out varchar2,
	P_URL								out varchar2
	) return varchar2
as
	------------------------------------------------------------------------------
	-- Function: 	Canonical Request
	-- Author:		Christina Moore
	-- Date:			25FEB2017
	-- Version:		0.3
	--
	-- Generates the Canonical Request and the corresponding URL
	-- as documented by AWS.
	-- http://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
	-- Their standard defintion looks like this:
	--		<HTTPMethod>\n
	--		<CanonicalURI>\n
	--		<CanonicalQueryString>\n
	--		<CanonicalHeaders>\n
	--		<SignedHeaders>\n
	--		<HashedPayload>
	-- 
	-- If AWS returns errors the cause is most likely found in the canonical 
	-- request.Even the signature doesn't match error. This is still likely 
	-- found in your canonical request. 
	--
	-- There are variations and judgement calls to make. For example, the AWS
	-- documentation will show you both of these two URL
	-- 		Option 1
	-- https://s3.amazonaws.com/examplebucket?prefix=somePrefix
	--		Option 2
	-- https://examplebucket.s3.amazonaws.com?prefix=somePrefix
	--
	-- What matters is that you stick to one patch until you hit a wall, then
	-- change paths and use the other option. In my errors, I have found that 
	-- Option 1 tends to be more robust. Option 2 tends to be shown with the
	-- introductory examples.
	--
	-- 25FEB2017 cmoore - additional notes on the Options above. The us-east-1
	-- also called us-standard doesn't follow the same canonical rules as other
	-- newer buckets. What works for eu-central-1 does not work for us-east-1.
	-- so I added an 'IF' statement. 
	--
	-- Revisions:
	--		0.2		cmoore 11feb2017
	--		left and right parens need to be escaped in the canonical request
	--		0.3		cmoore 25feb2017
	--			encountered error PermanentRedirect when using Option 1 above for eu-central-1. 
	--			Changing to option 2	
	--		0.4		cmoore 26feb2017
	--			with canonical URI, need to know if there is or is not a slash
	--
	------------------------------------------------------------------------------
	l_canonical_request varchar2(4000);
	l_http_method				varchar2(20);
	l_query_string			varchar2(1000);
	l_uri								varchar2(1000);
	l_header						varchar2(1000);
	l_signed_hdr				varchar2(1000);
	l_content_length		varchar2(100);
	l_bucket						varchar2(100);
	l_host							varchar2(100);
	l_request_hashed		varchar2(100);
begin
	validate_http_method(P_HTTP_METHOD,'canonical_request'); 
	l_query_string 			:= utl_url.escape(P_QUERY_STRING);
	
	-- Strip the ? in case someone adds the question-mark
	if substr(P_QUERY_STRING,1,1) = '?' then
			l_query_string := substr(l_query_string,2) ;
	end if; -- '? is first
	-- clean up the query string to meet AWS standards
	-- you do not want the slash in the query portion of the URL
	l_query_string	:= replace(l_query_string,'/','%2F');
	
	-- the ( and ) are unreserved characters in accordance to Oracle
	-- https://docs.oracle.com/database/121/ARPLS/u_url.htm#ARPLS71584
	l_query_string	:= replace(l_query_string,'(','%28');
	l_query_string	:= replace(l_query_string,')','%29');

	-- manage the canonical URI
	if P_BUCKET is not null then
		if g_aws_region in ('us-east-1') then
			-- Option 1 
			l_uri 		:= utl_url.escape('/' || P_BUCKET || P_CANONICAL_URI);
			l_host		:= 'host:s3.amazonaws.com';
			P_URL			:= utl_url.escape('https://s3.amazonaws.com/' || P_BUCKET || P_CANONICAL_URI);
		else
			-- Option 2
			case 
				when P_CANONICAL_URI is null then
					l_uri 		:= '/';
				when P_CANONICAL_URI = '/' then
					l_uri 		:= '/';
				else
					if substr(P_CANONICAL_URI,1,1) = '/' then
						l_uri 		:= utl_url.escape(P_CANONICAL_URI);
					else
						l_uri 		:= utl_url.escape('/' || P_CANONICAL_URI);
					end if; -- does canonical URI start with slash, add one if no
					
			end case;
			l_host	:= 'host:' || P_BUCKET || '.s3.' || g_aws_region || '.amazonaws.com';
			P_URL		:= utl_url.escape('https://' || P_BUCKET || '.s3.' ||  g_aws_region || '.amazonaws.com' || P_CANONICAL_URI);
		end if; -- us-east-1 or not
	else
		l_uri 		:= utl_url.escape(P_CANONICAL_URI);
		l_host		:= 'host:s3.amazonaws.com';
		P_URL			:= utl_url.escape('https://s3.amazonaws.com');
	end if; -- p_bucket null?
	
	l_header 		:= l_host || lf || 
								'x-amz-content-sha256:' || P_PAYLOAD_HASH || lf ||
								'x-amz-date:' || ISO_8601(P_DATE) || lf; -- this needs extra line?
	l_signed_hdr	:= 'host;x-amz-content-sha256;x-amz-date';
	
	l_canonical_request := P_HTTP_METHOD || lf ;
	l_canonical_request	:= l_canonical_request || l_uri || lf;
	l_canonical_request	:= l_canonical_request || l_query_string || lf;
	l_canonical_request	:= l_canonical_request || l_header || lf;
	l_canonical_request	:= l_canonical_request || l_signed_hdr || lf;
	l_canonical_request	:= l_canonical_request || P_PAYLOAD_HASH;

	-- this value can assist with troubleshooting errors from AWS
	P_CANONICAL_REQUEST	:= l_canonical_request;
	
	if P_QUERY_STRING is not null then
		if substr(P_QUERY_STRING,1,1) <> '?' then
			P_URL := P_URL || '?';
		end if; -- '? is first
		--l_query_string	:= replace(P_QUERY_STRING,'/','%2F');
		P_URL := P_URL || l_query_string;
	end if; -- query string null?
	
	l_request_hashed		:= lower(aws4_sha256(l_canonical_request));
	
	return l_request_hashed;
end canonical_request;

function signature_string (
	P_REQUEST_HASHED			in varchar2,
	P_DATE								in date
	) return varchar2
as
	------------------------------------------------------------------------------
	-- Function: 	Signature String
	-- Author:		Christina Moore
	-- Date:			04FEB2017
	-- Version:		0.1
	--
	-- Creates the StringToSign, in accordance with AWS API Documentation
	-- http://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
	-- 	
	--		"AWS4-HMAC-SHA256" + "\n" +
	--		timeStampISO8601Format + "\n" +
	--		<Scope> + "\n" +
	--		Hex(SHA256Hash(<CanonicalRequest>))
	--
	-- Revisions:
	--
	------------------------------------------------------------------------------
	l_response					varchar2(100);
	l_date_string				varchar2(50);
	l_time_string				varchar2(50);
	l_string_to_sign		varchar2(4000);
begin
	l_time_string :=  ISO_8601(P_DATE);
	l_date_string := to_char(P_DATE, 'YYYYMMDD');
	
	l_string_to_sign := g_aws4_auth   || lf;
	l_string_to_sign := l_string_to_sign || l_time_string || lf;
	l_string_to_sign := l_string_to_sign || l_date_string || '/' || g_aws_region || '/s3/aws4_request' || lf;
	l_string_to_sign := l_string_to_sign || P_REQUEST_HASHED;
	
	return(l_string_to_sign);
end signature_string;

function aws4_signature (
	P_REQUEST_HASHED			in varchar2,
	P_DATE								in date
	) return varchar2
as
	------------------------------------------------------------------------------
	-- Function: 	AWS4 Signature
	-- Author:		Christina Moore
	-- Date:			04FEB2017
	-- Version:		0.1
	--
	-- Parameters
	--	Request Hashed	- the Canonical Request that has been hashed
	--	Date - the date likely sysdate
	-- 
	-- Gets the String-To-Sign and hands it to the AWS Signing Key
	--
	-- Revisions:
	--
	------------------------------------------------------------------------------
	l_signature					varchar2(100);
	l_sign_string				varchar2(4000);
begin
	l_sign_string := signature_string(
		P_REQUEST_HASHED			=> P_REQUEST_HASHED,
		P_DATE								=> P_DATE
		);

	l_signature := aws4_signing_key(l_sign_string, P_DATE);
	return l_signature;
end aws4_signature;

function prep_aws_data (
	P_BUCKET						in varchar2,
	P_HTTP_METHOD				in varchar2,
	P_CANONICAL_URI			in varchar2,
	P_QUERY_STRING			in varchar2,
	P_DATE							in date,
	P_PAYLOAD_HASH			in varchar2,
	P_CONTENT_LENGTH		in number default null,
	P_CANONICAL_REQUEST	out varchar2,
	P_URL								out varchar2
	) return varchar2
as
	------------------------------------------------------------------------------
	-- Function: 	Prep AWS Data
	-- Author:		Christina Moore
	-- Date:			04FEB2017
	-- Version:		0.1
	--
	-- Returns		the AWS4 signature
	-- Parameters
	--	Bucket - name of the bucket
	-- 	HTTP Method - GET, POST, PUT
	-- 	Canonical URI	- most likely the /. Cleaner when using prefices
	-- 	Query String - These are likely derived from AWS parameters in their documentation
	--	Date - most likely sysdate
	--	Payload Hash - the SHA256 hash of the payload or a empty line (a constant)
	-- 	Canonical Request - this is returned to aid in debugging
	--	URL - needed to make the HTTPS call
	--
	-- http://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
	-- Task 1		Creates a Canonical Request
	--					And creates the URL so that they match. AWS docs are soft on this
	-- Task 2		Creates as String to Sign
	-- Task 3		Calculates Signature
	-- 	
	--
	-- Revisions:
	--
	------------------------------------------------------------------------------
	l_request_hashed		varchar2(100);
	l_signature					varchar2(100);
	l_url								varchar2(4000);
		
begin
	l_request_hashed := canonical_request (
		P_BUCKET							=> P_BUCKET,
		P_HTTP_METHOD					=> P_HTTP_METHOD,
		P_CANONICAL_URI				=> P_CANONICAL_URI,
		P_QUERY_STRING				=> P_QUERY_STRING,
		P_DATE								=> P_DATE,
		P_CANONICAL_REQUEST		=> P_CANONICAL_REQUEST,
		P_PAYLOAD_HASH				=> P_PAYLOAD_HASH,
		P_URL									=> P_URL
		);

	l_signature := aws4_signature (
		P_REQUEST_HASHED		=> l_request_hashed,
		P_DATE							=> P_DATE
		);

	return l_signature;
end prep_aws_data;
--------------------------------------------------------------------------------
-- 													S E C T I O N		
--
--						Private Functions and Procedures AWS S3 Interactions
--
--------------------------------------------------------------------------------

procedure check_for_errors (p_clob in clob)
as
  l_xml xmltype;
begin

  /*

  Purpose:   	check for errors (clob) in data returned from HTTPS call
							Overloaded procedure CLOB vs XML

  Remarks:

  Who     Date        Description
  ------  ----------  -------------------------------------
  MBR     15.01.2011  Created
	cmoroe	07FEB2017		Modified, reformatted

  */

  if (p_clob is not null) and (length(p_clob) > 0) then
    l_xml := xmltype (p_clob);
    if l_xml.existsnode('/Error') = 1 then
      debug_pkg.print (l_xml);
      raise_application_error (-20000, l_xml.extract('/Error/Message/text()').getstringval());
    end if;
  end if; -- p_clob is not null and > 0
end check_for_errors;

procedure check_for_errors (p_xml in xmltype)
as
begin

  /*

  Purpose:		check for errors (XMLType)
							Overloaded procedure CLOB vs XML

  Remarks:

  Who     Date        Description
  ------  ----------  -------------------------------------
  MBR     15.01.2011  Created
	cmoore	07FEB2017		modified, consolidated procedure, formatted

  */

  if p_xml.existsnode('/Error') = 1 then
    debug_pkg.print (p_xml);
    raise_application_error (-20000, p_xml.extract('/Error/Message/text()').getstringval());
  end if; -- error found in xml

end check_for_errors;

function check_for_redirect (p_clob in clob) return varchar2
as
  l_xml                          xmltype;
  l_returnvalue                  varchar2(4000);
begin

  /*

  Purpose:   check for redirect

  Remarks:   Used by the "delete bucket" procedure, by Jeffrey Kemp
             see http://code.google.com/p/plsql-utils/issues/detail?id=14
             "One thing I found when testing was that if the bucket is not in 
						 the US standard region, Amazon seems to respond with a 
						 TemporaryRedirect error. If the same request is re-requested to 
						 the indicated URL it works."

  Who     Date        Description
  ------  ----------  -------------------------------------
  MBR     16.02.2013  Created, based on code by Jeffrey Kemp

  */

  if (p_clob is not null) and (length(p_clob) > 0) then
    l_xml := xmltype (p_clob);
    if l_xml.existsnode('/Error') = 1 then
      if l_xml.extract('/Error/Code/text()').getStringVal = 'TemporaryRedirect' then
        l_returnvalue := l_xml.extract('/Error/Endpoint/text()').getStringVal;
        debug_pkg.printf('Temporary Redirect to %1', l_returnvalue);
      end if; -- TemporaryRedirect found
    end if; -- there is an error
  end if; -- clob not null and length > 0

  return l_returnvalue;
end check_for_redirect;

--------------------------------------------------------------------------------
-- 													S E C T I O N		
--
--						Functions and Procedures used for HTTPS auth and call
--						These should be kept alphabetized
--------------------------------------------------------------------------------
procedure delete_object (
	P_BUCKET			in varchar2,
	P_OBJECT			in varchar2
	)
	------------------------------------------------------------------------------
	-- Function: 	Delete Object
	-- Author:		Christina Moore
	-- Date:			11FEB2017
	-- Version:		0.1
	--
	-- Deletes an AWS S3 object
	-- Parameters
	-- 	Bucket - bucket name, lower case, exact as in S3
	--  Object - the object complete with prefix and name
	-- 
	-- Revisions:
	--
	------------------------------------------------------------------------------
as
	------------------------------------------------------------------------------
	--
	--	Sample Code for Calling Function
	--
	------------------------------------------------------------------------------
/*
begin
	aws4_s3_pkg.delete_object(
		p_bucket 			=> 'my-bucket',
		p_object			=> '/13 January 2014 letter to aunt.docx'
		);
end;
*/

	l_date							date;
	l_date_string				varchar2(50);
	l_time_string				varchar2(50);
	l_http_method				varchar2(10);
	l_query_string			varchar2(4000);
	l_signature					varchar2(4000);	
	l_canonical_request	varchar2(4000); 						-- used for debugging
	l_url								varchar2(4000);
	l_payload_hash			varchar2(100);
	l_clob							clob;

	
	-- notes on debugging
	-- 1. this calls the Alexandria DEBUG_PKG
	-- 2. You'll need to go into that package body and set m_debugging := true
	-- 3. You'll need to compile the Alexandria DEBUG_PKG Body
	-- 4. You'll then also need to turn the local debug option to true
	l_debug							boolean := true;
	
begin
	l_date							:= localtimestamp;
	l_date_string 			:= to_char(l_date, 'YYYYMMDD');
	l_time_string 			:= ISO_8601(l_date);
	l_http_method				:= 'DELETE';
	l_payload_hash 			:= g_null_hash;
	
	-- Query string is null, unless there is versionID data (not yet written)
	l_query_string			:= '';

	l_signature := prep_aws_data (
		P_BUCKET							=> P_BUCKET,
		P_HTTP_METHOD					=> l_http_method,
		P_CANONICAL_URI				=> P_OBJECT,
		P_QUERY_STRING				=> l_query_string,
		P_DATE								=> l_date,
		P_CANONICAL_REQUEST		=> l_canonical_request,
		P_PAYLOAD_HASH				=> l_payload_hash,
		P_URL									=> l_url
		);

	if l_debug then
		debug_pkg.print ('Canonical Request:', l_canonical_request);
		debug_pkg.print ('URL:', l_url);
	end if; -- l_debug
		
	apex_web_service.g_request_headers(1).name  := 'Authorization';
	apex_web_service.g_request_headers(1).value := g_aws4_auth  ||
			' Credential=' || g_aws_id || '/' || l_date_string || '/' || g_aws_region || '/s3/aws4_request,' ||
			' SignedHeaders=host;x-amz-content-sha256;x-amz-date,' ||
			' Signature=' || l_signature ;
		
	apex_web_service.g_request_headers(2).name 	:= 'x-amz-content-sha256';
	apex_web_service.g_request_headers(2).value := l_payload_hash ;

	apex_web_service.g_request_headers(3).name 	:= 'x-amz-date';
	apex_web_service.g_request_headers(3).value := l_time_string ;

	l_clob 	:= apex_web_service.make_rest_request(
			p_url               => l_url,
			p_http_method       => l_http_method,
			p_wallet_path				=> g_wallet_path,
			p_wallet_pwd				=> g_wallet_pwd
			);

	check_for_errors (l_clob);
end delete_object;

function get_bucket_list return t_bucket_list
	------------------------------------------------------------------------------
	-- Function: 	Get Bucket List
	-- Author:		Christina Moore
	-- Date:			10FEB2017
	-- Version:		0.1
	--
	-- Gets all of the buckets owned by the credentials provided
	-- Parameters
	-- 	t_bucket_list	- array of buckets, see the sample calling code
	--
	-- Revisions:
	--
	------------------------------------------------------------------------------
as
	l_date							date;
	l_date_string				varchar2(50);
	l_time_string				varchar2(50);
	l_payload_hash			varchar2(100);
	l_http_method				varchar2(10);
	l_request_hashed		varchar2(4000);
	l_canonical_request	varchar2(4000);
	l_signature					varchar2(4000);	
	l_url								varchar2(4000);
	l_clob							clob;
	l_xml               xmltype;
	l_count							number	:= 0;
	l_bucket_list				t_bucket_list;
		
	-- notes on debugging
	-- 1. this calls the Alexandria DEBUG_PKG
	-- 2. You'll need to go into that package body and set m_debugging := true
	-- 3. You'll need to compile the Alexandria DEBUG_PKG Body
	-- 4. You'll then also need to turn the local debug option to true
	l_debug							boolean := false;
	
	------------------------------------------------------------------------------
	--
	--	Sample Code for Calling Function
	--
	------------------------------------------------------------------------------
/*
declare
  l_bucket_list					aws4_s3_pkg.t_bucket_list;
begin

	l_bucket_list :=	aws4_s3_pkg.get_bucket_list;

	for i in 1 .. l_bucket_list.count loop
		dbms_output.put('Bucket: ');
		dbms_output.put(l_bucket_list(i).bucket_name);
		dbms_output.put(' Created: ');
		dbms_output.put_line(l_bucket_list(i).creation_date);
	end loop;
end;
*/

begin
	l_date 							:= localtimestamp;
	l_date_string 			:= to_char(l_date, 'YYYYMMDD');
	l_time_string 			:= ISO_8601(l_date);
	l_payload_hash 			:= g_null_hash;

	l_signature := prep_aws_data (
		P_BUCKET							=> null,
		P_HTTP_METHOD					=> 'GET',
		P_CANONICAL_URI				=> '/',
		P_QUERY_STRING				=> null,
		P_DATE								=> l_date,
		P_CANONICAL_REQUEST		=> l_canonical_request,
		P_PAYLOAD_HASH				=> l_payload_hash,
		P_URL									=> l_url
		);

	if l_debug then
		debug_pkg.print ('Canonical Request:');
		debug_pkg.print (l_canonical_request);
		debug_pkg.print ('URL:');
		debug_pkg.print (l_url);
	end if; -- l_debug

	apex_web_service.g_request_headers(1).name  := 'Authorization';
	apex_web_service.g_request_headers(1).value := 
		g_aws4_auth  ||
		' Credential=' || g_aws_id || '/' || l_date_string || '/' || g_aws_region || '/s3/aws4_request,' ||
		' SignedHeaders=host;x-amz-content-sha256;x-amz-date,' ||
		' Signature=' || l_signature ;
		
	apex_web_service.g_request_headers(2).name 	:= 'x-amz-content-sha256';
	apex_web_service.g_request_headers(2).value := l_payload_hash ;

	apex_web_service.g_request_headers(3).name 	:= 'x-amz-date';
	apex_web_service.g_request_headers(3).value := l_time_string ;

	l_clob 	:= APEX_WEB_SERVICE.MAKE_REST_REQUEST(
			p_url               => l_url,
			p_http_method       => 'GET',
			p_wallet_path				=> g_wallet_path,
			p_wallet_pwd				=> g_wallet_pwd
			);

  if (l_clob is not null) and (length(l_clob) > 0) then
    l_xml := xmltype (l_clob);
    check_for_errors (l_xml);

    for l_rec in (
				select 
					extractValue(value(t), '*/Name', g_aws_namespace_s3_full) as bucket_name,
					extractValue(value(t), '*/CreationDate', g_aws_namespace_s3_full) as creation_date
				from table(xmlsequence(l_xml.extract('//ListAllMyBucketsResult/Buckets/Bucket', g_aws_namespace_s3_full))) t
      ) loop
				l_count := l_count + 1;
				l_bucket_list(l_count).bucket_name 		:= l_rec.bucket_name;
				l_bucket_list(l_count).creation_date 	:= to_date(l_rec.creation_date, g_date_format_xml);
    end loop; -- loop xml data
  end if; -- is clob from S3 null?

  return l_bucket_list;
end get_bucket_list;

function get_bucket_tab return t_bucket_tab pipelined
as
  l_bucket_list                  t_bucket_list;
begin

  /*

  Purpose:   get buckets

  Remarks:

  Who     Date        Description
  ------  ----------  -------------------------------------
  MBR     19.01.2011  Created

  */

  l_bucket_list := get_bucket_list;

  for i in 1 .. l_bucket_list.count loop
    pipe row (l_bucket_list(i));
  end loop;

  return;

end get_bucket_tab;

procedure get_object_list (
	P_BUCKET			in varchar2,
	P_PREFIX			in varchar2,
	P_MAX_KEYS		in number,
	P_OBJECT_LIST	out t_object_list
	)
	------------------------------------------------------------------------------
	-- Function: 	Get Object list
	-- Author:		Christina Moore
	-- Date:			10FEB2017
	-- Version:		0.1
	--
	-- Get a list of the Objects within a bucket
	-- Parameters
	-- 	Bucket - bucket name, lower case, exact as in S3
	--  Prefix - the folder (AWS calls it a prefix)
	--	Max Keys	-- maximum number of objects to return (1000 is a hard max)
	-- Results are returned in P_OBJECT_LIST
	-- 
	-- Prefix - do not shart with a slash
	-- Max Keys is a parameter sent to AWS. If the number of keys exceeds the
	-- max keys, you will get TRUE on IsTruncated. if you ask for 10 keys
	-- and there are more than 10 keys, you will get 10 keys and 
	-- IsTruncated = TRUE. 
	-- 
	-- Revisions:
	--
	------------------------------------------------------------------------------
as
	------------------------------------------------------------------------------
	--
	--	Sample Code for Calling Function
	--
	------------------------------------------------------------------------------
/*
declare
  l_object_list					aws4_s3_pkg.t_object_list;
begin

	aws4_s3_pkg.get_object_list(
		p_bucket 			=> 'tempest-software',
		p_prefix			=> 'STORMPETREL/000000161/000000125/',
		p_max_keys		=> 1000,
		p_object_list	=> l_object_list
		);

	-- how many items returned
	dbms_output.put_line('Object Count = ' || to_char(l_object_list.count));

	-- list the objects
	for i in 1 .. l_object_list.count loop
		dbms_output.put('Object: ');
		dbms_output.put(l_object_list(i).key);
		dbms_output.put(' Size Bytes: ');
		dbms_output.put(l_object_list(i).size_bytes);
		dbms_output.put(' Last: ');
		dbms_output.put_line(l_object_list(i).last_modified);
	end loop;
end;
*/

	l_date							date;
	l_date_string				varchar2(50);
	l_time_string				varchar2(50);
	l_http_method				varchar2(10);
	l_query_string			varchar2(4000);
	l_query_string_root	varchar2(4000);
	l_canonical_uri			varchar2(100) := '/';
	
	l_more							boolean := true;
  l_count             pls_integer := 0;
	l_max_keys					number := 100000; -- safety valve on loop
	l_signature					varchar2(4000);	

	l_canonical_request	varchar2(4000); -- used for debugging
	l_url								varchar2(4000);
	l_payload_hash			varchar2(100);

	l_clob							clob;
	l_xml               xmltype;
  l_object_list     	t_object_list;
	l_last_key					varchar2(1000);
	
	-- notes on debugging
	-- 1. this calls the Alexandria DEBUG_PKG
	-- 2. You'll need to go into that package body and set m_debugging := true
	-- 3. You'll need to compile the Alexandria DEBUG_PKG Body
	-- 4. You'll then also need to turn the local debug option to true
	l_debug							boolean := false;
	
begin
	l_date							:= localtimestamp;
	l_date_string 			:= to_char(l_date, 'YYYYMMDD');
	l_time_string 			:= ISO_8601(l_date);
	l_http_method				:= 'GET';
	l_payload_hash 			:= g_null_hash;
	
	-- List Object Version 2 requires list-type=2
	l_query_string		:= 'list-type=2';
	if P_MAX_KEYS is not null then
		l_query_string 		:= l_query_string || '&max-keys=' || trim(to_char(P_MAX_KEYS));		
		l_max_keys				:= P_MAX_KEYS;
	end if; -- max keys null

	if P_PREFIX is not null then
		l_query_string 		:= l_query_string || '&prefix=' || P_PREFIX;
	end if;
	l_query_string_root	:= l_query_string;


	while l_more and l_count < l_max_keys loop	
		l_signature := prep_aws_data (
			P_BUCKET							=> P_BUCKET,
			P_HTTP_METHOD					=> l_http_method,
			P_CANONICAL_URI				=> l_canonical_uri,
			P_QUERY_STRING				=> l_query_string,
			P_DATE								=> l_date,
			P_CANONICAL_REQUEST		=> l_canonical_request,
			P_PAYLOAD_HASH				=> l_payload_hash,
			P_URL									=> l_url
			);

		if l_debug then
			debug_pkg.print ('Canonical Request:');
			debug_pkg.print (l_canonical_request);
			debug_pkg.print ('URL:');
			debug_pkg.print (l_url);
		end if; -- l_debug
		
		apex_web_service.g_request_headers(1).name  := 'Authorization';
		apex_web_service.g_request_headers(1).value := g_aws4_auth  ||
				' Credential=' || g_aws_id || '/' || l_date_string || '/' || g_aws_region || '/s3/aws4_request,' ||
				' SignedHeaders=host;x-amz-content-sha256;x-amz-date,' ||
				' Signature=' || l_signature ;
			
		apex_web_service.g_request_headers(2).name 	:= 'x-amz-content-sha256';
		apex_web_service.g_request_headers(2).value := l_payload_hash ;
	
		apex_web_service.g_request_headers(3).name 	:= 'x-amz-date';
		apex_web_service.g_request_headers(3).value := l_time_string ;

		l_clob 	:= apex_web_service.make_rest_request(
				p_url               => l_url,
				p_http_method       => l_http_method,
				p_wallet_path				=> g_wallet_path,
				p_wallet_pwd				=> g_wallet_pwd
				);

		if (l_clob is not null) and (dbms_lob.getlength(l_clob) > 0) then
			l_xml := xmltype (l_clob);
			check_for_errors (l_xml);
	
			for l_rec in (
				select 
					extractValue(value(t), '*/Key', g_aws_namespace_s3_full) as key,
					extractValue(value(t), '*/Size', g_aws_namespace_s3_full) as size_bytes,
					extractValue(value(t), '*/LastModified', g_aws_namespace_s3_full) as last_modified
				from table(xmlsequence(l_xml.extract('//ListBucketResult/Contents', g_aws_namespace_s3_full))) t
				) loop
					l_count := l_count + 1;
					l_object_list(l_count).key := l_rec.key;
			
					l_object_list(l_count).size_bytes := l_rec.size_bytes;
					l_object_list(l_count).last_modified := to_date(l_rec.last_modified, g_date_format_xml);
			end loop; -- loop xml data
	
			-- check if this is the last set of data or not
			l_xml := l_xml.extract('//ListBucketResult/IsTruncated/text()', g_aws_namespace_s3_full);
			if l_xml is not null and l_xml.getStringVal = 'true' then
				l_last_key		:= l_object_list(l_object_list.last).key;
				l_more				:= true;
			else
				l_more				:= false;
				l_last_key		:= null;
			end if; -- end of the list?

		end if; -- AWS clob is not null
		
		-- Prepare for the next iteration
		l_query_string			:= l_query_string_root || amp || 'start-after=' || l_last_key ;
		
	end loop; -- get all records and safety valve
	P_OBJECT_LIST := l_object_list;
end get_object_list;

function get_object_url (
	P_BUCKET						in varchar2,
	P_CANONICAL_URI			in varchar2,
	P_DATE							in date,
	P_EXPIRY						in number default 3600
	) return varchar2
	------------------------------------------------------------------------------
	-- Function: 	Signature String
	-- Author:		Christina Moore
	-- Date:			09FEB2017
	-- Version:		0.1
	--
	-- Created the URL to download an object from AWS S3
	-- Parameters
	-- 	Bucket - bucket name, lower case, exact as in S3
	--	Canonical URI - the document key e.g. folder and document name.
	-- 	Date	- the date
	--  Expiry	- expiration of the request in seconds. Defaults to 5 min
	-- 
	--
	-- Revisions:
	--
	------------------------------------------------------------------------------
as
	l_bucket						varchar2(50);
	l_date_string				varchar2(50);
	l_time_string				varchar2(50);
	l_expiry						varchar2(10);
	l_host							varchar2(50);
	l_url								varchar2(4000);
	l_req_canonical			varchar2(1000);
	l_algo							varchar2(4000);	
	l_request 					varchar2(4000);
	l_request_hashed		varchar2(1000);
	l_string_to_sign		varchar2(4000);
	l_signature					varchar2(1000);
	
begin
	if P_BUCKET is null then
		raise_application_error (-20000,
			'Bucket Name is null in aws4_s3_pkg.presign_canonical_request'); 
	else
		l_bucket := lower(P_BUCKET);
	end if;
	l_date_string 	:= to_char(P_DATE, 'YYYYMMDD');
	l_time_string		:= iso_8601(P_DATE);
	l_expiry				:= trim(to_char( P_EXPIRY ));
	
	-- manage the bucket name
	l_host 					:= 'host:s3.amazonaws.com';
	l_url						:= 'https://s3.amazonaws.com/' || l_bucket;
	
	-- manage the canonical URI
	l_url						:= utl_url.escape(l_url || P_CANONICAL_URI);
	l_req_canonical := utl_url.escape('/' || P_BUCKET || P_CANONICAL_URI);
	
	-- manage the algorithm
	l_algo					:= 'X-Amz-Algorithm=AWS4-HMAC-SHA256&' ||
												'X-Amz-Credential=' || g_aws_id || slsh || 
												l_date_string 			|| slsh ||
												g_aws_region 				|| slsh ||
												's3' 								|| slsh ||
												'aws4_request'			|| amp 	||
												'X-Amz-Date='				|| l_time_string || amp ||
												'X-Amz-Expires=' 		|| l_expiry || amp || 
												'X-Amz-SignedHeaders=host';

	l_url			:= l_url || '?' || l_algo;
	
	-- Build the Canonical Request
	l_request := 'GET' || lf ;
	l_request	:= l_request || l_req_canonical || lf;
	l_request	:= l_request || l_algo || lf;
	l_request	:= l_request || l_host || lf;
	l_request	:= l_request || lf;
	l_request	:= l_request || 'host' || lf;
	l_request	:= l_request || 'UNSIGNED-PAYLOAD';

	-- Hash the Canonical Request	
	l_request_hashed	:= lower(aws4_sha256(l_request));
	
	--dbms_output.put_line('Canonical Request:' );
	--dbms_output.put_line(	l_request );
	
	-- Generate the String to Sign
	l_string_to_sign 	:= signature_string(
		P_REQUEST_HASHED			=> l_request_hashed,
		P_DATE								=> P_DATE
		);
		
	--dbms_output.put_line('string_to_sign:');	
	--dbms_output.put_line(l_string_to_sign);	
	
	-- Generate the Signature
	l_signature 				:= aws4_signing_key(
		P_STRING_TO_SIGN		=> l_string_to_sign,
		P_DATE							=> P_DATE
		);
		
	--dbms_output.put_line('signature:');	
	--dbms_output.put_line(l_signature);	

	-- add signature to the URL
	l_url		:= l_url || amp || 
							'X-Amz-Signature=' || l_signature;
	
	-- Return the URL
	return l_url;
end get_object_url;

procedure put_object (
	P_BUCKET				in varchar2,
	P_BLOB					in blob,
	P_OBJECT_KEY		in varchar2,
	P_MIMETYPE			in varchar2
)
	------------------------------------------------------------------------------
	-- Function: 	Put Object
	-- Author:		Christina Moore
	-- Date:			11FEB2017
	-- Version:		0.1
	--
	-- Puts a blob on S3
	-- Parameters
	-- 	Bucket - bucket name, lower case, exact as in S3
	-- 	BLOB	- the blob
	--	Object key - the filename plus the prefix 
	-- 	Mimetype - the mimetype of the blob
	-- 
	--
	-- Revisions:
	--
	------------------------------------------------------------------------------
as
	------------------------------------------------------------------------------
	--
	--	Sample Code for Calling Procedure
	--
	------------------------------------------------------------------------------
/*
declare
	l_filename				varchar2(100);
	l_blob						blob;
	l_mimetype				varchar2(100);
	l_content_length	number;
	
begin
	select
		doc_blob,
		doc_mimetype,
		doc_filename,
		dbms_lob.getlength(doc_blob)
	into
		l_blob,
		l_mimetype,
		l_filename,
		l_content_length
	from tg_document
	where doc_pk = 5;
	
	--dbms_output.put_line('filename:' || l_filename);
	--dbms_output.put_line('Mime Type: ' || l_mimetype);
	--dbms_output.put_line('Content Length: ' || trim(to_char(l_content_length)));
	
	l_filename := '/' || l_filename;
	
	aws4_s3_pkg.put_object(
		P_BUCKET				=> '74-winchester-archive',
		P_BLOB					=> l_blob,
		P_OBJECT_KEY		=> l_filename,
		P_MIMETYPE			=> l_mimetype
	);

end;
*/
	l_date							date;
	l_date_string				varchar2(50);
	l_time_string				varchar2(50);
	l_http_method				varchar2(10);
	l_query_string			varchar2(4000);
	l_query_string_root	varchar2(4000);
	l_canonical_uri			varchar2(100) := '/';
	l_signature					varchar2(4000);	
	l_canonical_request	varchar2(4000); -- used for debugging
	l_url								varchar2(4000);
	l_payload_hash			varchar2(100);

	l_clob							clob;
	l_xml               xmltype;

	l_content_length		number;
	
	-- notes on debugging
	-- 1. this calls the Alexandria DEBUG_PKG
	-- 2. You'll need to go into that package body and set m_debugging := true
	-- 3. You'll need to compile the Alexandria DEBUG_PKG Body
	-- 4. You'll then also need to turn the local debug option to true
	l_debug							boolean := true;
	
begin
	l_date							:= localtimestamp;
	l_date_string 			:= to_char(l_date, 'YYYYMMDD');
	l_time_string 			:= ISO_8601(l_date);
	l_http_method				:= 'PUT';
	l_query_string			:= '';
	
	-- calculate the payload hash
	l_payload_hash 			:= aws4_sha256(P_BLOB);

	-- calculate the content length
	l_content_length		:= dbms_lob.getlength(P_BLOB);
	
	l_signature := prep_aws_data (
		P_BUCKET							=> P_BUCKET,
		P_HTTP_METHOD					=> l_http_method,
		P_CANONICAL_URI				=> P_OBJECT_KEY,
		P_QUERY_STRING				=> l_query_string,
		P_DATE								=> l_date,
		P_CONTENT_LENGTH			=> l_content_length,
		P_CANONICAL_REQUEST		=> l_canonical_request,
		P_PAYLOAD_HASH				=> l_payload_hash,
		P_URL									=> l_url
		);

	if l_debug then
		debug_pkg.print ('payload_hash', l_payload_hash);	
		debug_pkg.print ('Canonical Request', l_canonical_request );
		debug_pkg.print ('URL', l_url);
	end if; -- l_debug
		
	apex_web_service.g_request_headers(1).name  := 'Authorization';
	apex_web_service.g_request_headers(1).value := g_aws4_auth  ||
			' Credential=' || g_aws_id || '/' || l_date_string || '/' || g_aws_region || '/s3/aws4_request,' ||
			' SignedHeaders=host;x-amz-content-sha256;x-amz-date,' ||
			' Signature=' || l_signature ;
		
	apex_web_service.g_request_headers(2).name 	:= 'x-amz-content-sha256';
	apex_web_service.g_request_headers(2).value := l_payload_hash ;

	apex_web_service.g_request_headers(3).name 	:= 'x-amz-date';
	apex_web_service.g_request_headers(3).value := l_time_string;
	
	apex_web_service.g_request_headers(4).name 	:= 'Content-Type';
	apex_web_service.g_request_headers(4).value := nvl(P_MIMETYPE, 'application/octet-stream');

	apex_web_service.g_request_headers(5).name 	:= 'Content-Length';
	apex_web_service.g_request_headers(5).value := l_content_length;

		l_clob 	:= apex_web_service.make_rest_request(
				p_url               => l_url,
				p_http_method       => l_http_method,
				p_wallet_path				=> g_wallet_path,
				p_wallet_pwd				=> g_wallet_pwd,
				p_body_blob					=> P_BLOB
				);

end put_object;

end aws4_s3_pkg;
