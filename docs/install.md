We really can't have a slick installation script. There are too many things to change in the package body.

# Required
## AWS Account
Yes, you need an AWS account. You need a S3 user with full access. You will need your:

- AWS Access Key ID
- AWS Secret Key
Check with AWS documentation on these steps. Don't get fancy with security at AWS. Give your AWS S3 user full access to start. 
Let your troubleshooting focus on PL/SQL or APEX. When you get it all the Oracle stuff dialed in and working, then you can 
twiddle around with the AWS security. 

## Oracle Wallet
You will need the ability to run the APEX_WEB_SERVICE.MAKE_REST_REQUEST with HTTPS. This will mean installing the AWS S3 certs
into your Oracle instances. I did notice that AWS uses different certs for S3. The ones that work (February 2017) are:
- DigiCert_Baltimore_Root (expires 5/12/2025)
- DigiCert_Baltimore_CA-2_G2 (expires 5/10/2025)
I do not know if these certs are used in all regions. I will upload these two certs to make life a little easier. These certs
do work for us-east-1 (N. Virginia)

## DEBUG_PKG
You should install the Alexandria Library debug_pkg. I can't find the link right now. If you don't have it, comment those
lines out. They are easy to find. They will trip your compiler!

## Package Changes
You will need to make the following changes in your package body:

1. g_aws_id - change to your AWS ID. It seems to be the short of the two that AWS provides. Key is in both words, so that does confuse.
2. g_aws_key - change your AWS Key. This is the longer of the two.
3. g_wallet_path - you'll need your wallet path. The example here is from our Windows based server.
4. g_wallet_pwd - your wallet password
5. g_gmt_offset - we use UTC on all of our servers. I never tested with another timezone. Try it!
6. g_aws_region - Set this to your AWS region. There is a full list in the package specifications

# Nice to Have
## A Quick CLOB table
Having at simple clob table is nice to have at hand:
- Primary Key
- CLOB
- Timestamp
This can help with troubleshooting responses from AWS. Parsing large CLOBs in dbms_output can be ugly. Formatting, spaces and 
and linefeed are a matter of precision with AWS. 

## Debug Tool
It is nice to have a debug tool that allows you to trace your work. The one we use is non-standard. I tossed in a few
references to the DEBUG too. 

## BLOB Table
Nice to have a quick table with a BLOB. Makes putting files up easier. Might think of including fields for PREFIX and BUCKET
as well as the standard BLOB, MIMETYPE, FILENAME.
