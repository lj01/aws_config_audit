##This tool audits all CloudFront configurations in a single aws account if they follow the default spec##

##This needs the relevant account ID and ACL ID. 


import boto3


client = boto3.client('config')

client = boto3.client('cloudfront')


########ADD ACL ID AND ACCOUNT NUMBER

response = client.list_distributions_by_web_acl_id(

WebACLId='xxxxxxxxxxx'
)

#####Add Account Number ###########

AcctNumber = "xxxxxxxxxxx"

if AcctNumber in response['DistributionList']['Items'][0]['ARN']:

    print('\n')

    print('************* COMPLIANCE AUDIT FOR ACCOUNT: ' + AcctNumber +' *************')

    print('\n')

###########check cache one min TTL for static assets - if origin is S3 bucket, it is static asset, otherwise it is dynamic asset###########


    checkTTL = response['DistributionList']['Items'][0]['DefaultCacheBehavior']

    print('TTL COMPLIANT?')

    if 'S3' in checkTTL['TargetOriginId']:
        print('This is a static asset')
        if (checkTTL['DefaultTTL']) == 60:
            print('COMPLIANT - DefaultTTL is one minute')
        else:
            print('NOT COMPLIANT - DefaultTTL is not one minute')
    elif 'S3' not in checkTTL['TargetOriginId']:
        print('This is a dynamic asset')
        if (checkTTL['DefaultTTL']) == 0:
            print('COMPLIANT - Default TTL is zero seconds')

    print('\n')


##########check if cookies passed to origin#################

    print('COOKIES PASSED TO ORIGIN?')

    checkCookies = response['DistributionList']['Items'][0]['DefaultCacheBehavior']['ForwardedValues']['Cookies']

    if (checkCookies['Forward']) == 'All':
        print('COMPLIANT - all cookies passed to origin')
    else:
        print('NOT COMPLIANT - cookies not passed to origin')

    print('\n')


##########check if query strings passed to origin#################

    print('QUERYSTRINGS PASSED TO ORIGIN?')

    checkQueryString = response['DistributionList']['Items'][0]['DefaultCacheBehavior']['ForwardedValues']

    if (checkQueryString['QueryString']) == 'All':
        print('COMPLIANT - all querystrings passed to origin')
    else:
        print('NOT COMPLIANT - querystrings not passed to origin')

    print('\n')


#############check if HEAD/GET requests can be cached by CDN###########

    print('HEAD/GET CAN BE CACHED BY CDN?')

    checkHGrequestsCached = response['DistributionList']['Items'][0]['DefaultCacheBehavior']['AllowedMethods']

    if ('HEAD' and 'GET') in checkHGrequestsCached['Items']:
        print('COMPLIANT - HEAD and GET can be cached by CDN')
    else:
        print('NOT COMPLIANT - HEAD and GET cannot be cached by CDN')

    print('\n')


#############POST/PUT/DELETE requests should be passed to origin##############

    print('POST/PUT/DELETE REQUESTS PASSED TO ORIGIN?')

    checkPPDPassedToOrigin = response['DistributionList']['Items'][0]['DefaultCacheBehavior']['AllowedMethods']['CachedMethods']

    if any('PUT' or 'POST' or 'DELETE') in checkPPDPassedToOrigin['Items']:
        print('NOT COMPLIANT - should be passed to Origin and not in cached list')
    else:
        print('COMPLIANT - put, post and delete requests are being passed to Origin')

    print('\n')


#############POST/PUT/DELETE requests should be disabled if origin is S3############

    print('POST/PUT/DELETE REQUESTS DISABLED IF ORIGIN IS S3')

    checkS3OriginHGDisabled = response['DistributionList']['Items'][0]['DefaultCacheBehavior']

    if 'S3' in checkS3OriginHGDisabled['TargetOriginId']:
        print('Origin is S3')

        if 'POST' or 'PUT' or 'DELETE' in checkS3OriginHGDisabled['TargetOriginId']['AllowedMethods']['Items']:
            print('NOT COMPLIANT - POST/PUT/DELETE from S3 origin are not disabled')
        else:
            print('COMPLIANT - POST/PUT/DELETE from S3 origin are disabled')

        print('\n')


#############HEAD/GET can be passed to origin############

    print('HEAD/GET REQUESTS CAN BE PASSED TO ORIGIN')

    checkCachedMethods = response['DistributionList']['Items'][0]['DefaultCacheBehavior']['AllowedMethods']['CachedMethods']

    if (checkCachedMethods['Items'][0]) == 'HEAD' and (checkCachedMethods['Items'][1]) =='GET':
        print('COMPLIANT - HEAD/GET requests can be passed to origin')
    else:
        print('NOT COMPLIANT - HEAD/GET requests cannot be passed to origin')

    print('\n')


############HTTP Headers can be whitelisted to pass CDN if required by origin CACHE WHITELIST OR NONE###########

    print('HTTP HEADERS CAN BE WHITELISTED TO PASS CDN IF REQUIRED BY ORIGIN')

    checkWhitelisted = response['DistributionList']['Items'][0]['DefaultCacheBehavior']['ForwardedValues']

    if 'whitelist' in checkWhitelisted['Cookies'] and 'all' not in checkWhitelisted['Cookies']:
        print('COMPLIANT - Whitelist allowed')
    else:
        print('NOT COMPLIANT - whitelist not allowed')
