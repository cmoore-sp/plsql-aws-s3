CREATE OR REPLACE EDITIONABLE PACKAGE "AWS4_S3_PKG" as

  type t_bucket is record (
    bucket_name varchar2(255),
    creation_date date
  );

  type t_bucket_list is table of t_bucket index by binary_integer;
  type t_bucket_tab is table of t_bucket;

	-- NOTE this is changed to capture the version ID cmoore february 2017
  type t_object is record (
    key varchar2(4000),
    size_bytes number,
    last_modified date,
		version_id	varchar2(4000)
  );

  type t_object_list is table of t_object index by binary_integer;
  type t_object_tab is table of t_object;

  type t_owner is record (
    user_id varchar2(200),
    user_name varchar2(200)
  );

  type t_grantee is record (
    grantee_type varchar2(20),  -- CanonicalUser or Group
    user_id varchar2(200),      -- for users
    user_name varchar2(200),    -- for users
    group_uri varchar2(200),    -- for groups
    permission varchar2(20)     -- FULL_CONTROL, WRITE, READ_ACP
  );

  type t_grantee_list is table of t_grantee index by binary_integer;
  type t_grantee_tab is table of t_grantee;

  -- bucket regions
  -- see http://aws.amazon.com/articles/3912?_encoding=UTF8-jiveRedirect=1#s3
  -- Updated 09FEB2017 cmoore
	-- see http://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region
  g_region_us_standard           constant varchar2(255) := 'us-east-1'; 
	g_region_us_east_virginia	     constant varchar2(255) := 'us-east-1'; 
  g_region_us_west_oregon        constant varchar2(255) := 'us-west-2';
	g_region_eu_ireland          	 constant varchar2(255) := 'eu-west-1';
  g_region_asia_pacific_tokyo    constant varchar2(255) := 'ap-northeast-1';
  g_region_asia_pacific_singapor constant varchar2(255) := 'ap-southeast-1';
  g_region_asia_pacific_sydney   constant varchar2(255) := 'ap-southeast-2';
  g_region_south_america_sao_p   constant varchar2(255) := 'sa-east-1';

	-- The following sites are AWS Version 4 only
	g_region_eu_london          	 constant varchar2(255) := 'eu-west-2';
	g_region_us_east_ohio			     constant varchar2(255) := 'us-east-2';	
	g_region_canada_central_1      constant varchar2(255) := 'ca-central-1';
  g_region_us_west_california    constant varchar2(255) := 'us-west-1';
	g_region_asia_pacific_mumbai 	 constant varchar2(255) := 'ap-south-1';		
	g_region_asia_pacific_seoul 	 constant varchar2(255) := 'ap-northeast-2';	
	g_region_eu_frankfurt          constant varchar2(255) := 'eu-central-1';

  -- predefined access policies
  -- see http://docs.amazonwebservices.com/AmazonS3/latest/dev/index.html?RESTAccessPolicy.html
  g_acl_private                  constant varchar2(255) := 'private';
  g_acl_public_read              constant varchar2(255) := 'public-read';
  g_acl_public_read_write        constant varchar2(255) := 'public-read-write';
  g_acl_authenticated_read       constant varchar2(255) := 'authenticated-read';
  g_acl_bucket_owner_read        constant varchar2(255) := 'bucket-owner-read';
  g_acl_bucket_owner_full_ctrl   constant varchar2(255) := 'bucket-owner-full-control';


--------------------------------------------------------------------------------
-- 													S E C T I O N		
--
--						Functions and Procedures used for HTTPS auth and call
--						These should be kept alphabetized
--
-- Modifications:
--		2018-OCT-22 cmoore, added AWS4_SHA256 to publicly available functions
--------------------------------------------------------------------------------
	
function aws4_sha256 (
	P_STRING			varchar2
	) return varchar2;
	
function aws4_sha256 (
	P_BLOB			in blob
	) return varchar2;
	
function ISO_8601 (
		P_DATE		in timestamp,
		P_TIMEZONE	in varchar2 default 'UTC'
		) return varchar2;

procedure delete_object (
	P_BUCKET						in varchar2,
	P_OBJECT						in varchar2
	);

function bucket_head (
	P_BUCKET			in varchar2
	) return boolean;
	
function get_bucket_list 
	return t_bucket_list;

function get_bucket_tab 
	return t_bucket_tab pipelined;

function get_object_blob (
	P_BUCKET					in varchar2,
	P_CANONICAL_URI		in varchar2
	) return blob;
	
function get_object_blob2 (
	P_URL							in varchar2
	) return blob;
	
procedure get_object_list (
	P_BUCKET			in varchar2,
	P_PREFIX			in varchar2,
	P_MAX_KEYS		in number,
	P_OBJECT_LIST	out t_object_list
	);

function get_object_url (
	P_BUCKET						in varchar2,
	P_CANONICAL_URI			in varchar2,
	P_DATE							in date,
	P_EXPIRY						in number default 3600
	) return varchar2;

procedure object_head (
	P_BUCKET					in varchar2,
	P_PREFIX					in varchar2,
	P_OBJECT    			in varchar2,
  P_ETAG        		out varchar2,
  P_LENGTH      		out number,
  P_CREATE_DATE 		out date,
  P_MODIFIED_DATE  	out date
);

procedure put_object (
	P_BUCKET				in varchar2,
	P_BLOB					in blob,
	P_OBJECT_KEY		in varchar2,
	P_MIMETYPE			in varchar2
	);
	
end aws4_s3_pkg;
