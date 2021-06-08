# June 2021
I did nothing to maintain the PL/SQL code for the AWS S3 interface at my GitHub site for the last years. I know we had run into issues with bugs and such. The most common error is that our Oracle code and AWS disagreed about the time. Often it was the time zone offset from UTC. 
I am not going to reconcile the old code with new. Instead, the code we’ve run in production is being posted. It is backwards compatible. 
Please take from it as you will and enjoy.


# Oracle PL/SQL AWS S3 with HTTPS
Please help me improve this API with Amazon Web Services (AWS) for S3 (Simple Storage Service). AWS has upgraded their 
S3 services and the API to include an encrypted HTTP interface. The very good work done by the team that included
Morten Braten and Jason Straub pre-dates the HTTPS API. Furthermore, the transition to HTTPS was not as simple as adding
and 'S' to the call. 

As of February 2017, I have taken the package to the level that is needed for my company. It is possible to:

1. List objects (files)

2. List all buckets

3. Upload an object

4. Delete an object

AWS S3 has a lot more features than those present in this package. 

# Revisions
May 2018 added\fixed the following:
* Escaping ampersand in filenames (download URL was failing if filename had ampersand)
* Added function to fetch a blob from an HTTPS site
* Added function to get an AWS S3 object via HTTPS

# PL/SQL Code
Because the authentication process was so very different than the original effort found in the [Alexandria AMAZON_AWS_S3_PKG](https://github.com/mortenbra/alexandria-plsql-utils),
I had the freedom to take advantage a few improved tools in PL/SQL such as apex_web_service.make_rest_request which means
the package uses the Oracle Wallet and Password. There are techniques for proxying the HTTPS. This was not in our
interest because we want the payload encrypted end-to-end. 

## Alexandria Library
Yes, this package does belong in the Alexandria library. I think it needs a little more effort, debugging, and lovin' before
it earns a spot there. 

# AWS S3 History
The early days of S3 did not include regions. [S3 now includes regions](http://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region). Some regions permit unsecure HTTP. About 50% of the 
regions require HTTPS and require the AWS4 signature process. I have not seen dates when AWS will obsolete the older
authentication process and mandate HTTPS across the board. 

We use AWS S3 in our commercial Oracle APEX applications. It became imparative to get ahead of the curve. Also we wanted
to improve our security posture. All Trumping aside, the statement "all communications over the internet are encrypted" is
only possible is we affirmatively encrypted the AWS S3 communication too. 

AWS S3 feature set has grown over the recent years too. 

# Other API
AWS has mutliple application programming interfaces. There is a solid command line tool. Their web-based tools are good and
improving. And Amazon provides API in other languages (just not PL/SQL). The decision in what to include is focused on what 
would a database application need to do (and what does my company need). I would argue it is not necessary to build an API
in PL/SQL that replicates 100% of what is possible. 

# More Documentation
A list of additional documents included:

1. [AWS Documentation Comments](docs/aws_docs.md)
2. [Installation Notes](docs/install.md)
3. [Coding Guidelines](docs/code_standards.md)
