/*
* Copyright (c) 2006-2006 Nokia Corporation and/or its subsidiary(-ies).
* All rights reserved.
* This component and the accompanying materials are made available
* under the terms of "Eclipse Public License v1.0"
* which accompanies this distribution, and is available
* at the URL "http://www.eclipse.org/legal/epl-v10.html".
*
* Initial Contributors:
* Nokia Corporation - initial contribution.
*
* Contributors:
*
* Description:           
*
*/










#include "sencryptoutils.h"
#include <imcvcodc.h>
#include "senguidgen.h"
#include <e32math.h>
#include <SenDomFragment.h>
#include <SenNameSpace.h>
#include "SenWsSecurityHeader.h"
//#include "senxmldebug.h"

namespace
    {
    _LIT(KTimeReference,         "19700000:000000");
    const TInt KToBase64CoefficientNumerator  = 4;
    const TInt KToBase64CoefficientNominative = 3;
    const TInt KInt64Length = 20;
	const TInt KInt32Length = 10;
	const TInt KHexWidth = 2;
    }

EXPORT_C HBufC8* SenCryptoUtils::GetPSHA1HashL( const TDesC8& aSecret, 
                                                const TDesC8& aSeed, 
                                                const TInt aLength )
{
    HBufC8* output = HBufC8::NewLC(aLength);

    CSHA1* sha1 = CSHA1::NewL();    
    CleanupStack::PushL(sha1);

    CHMAC* hmac = CHMAC::NewL(aSecret, sha1);
    CleanupStack::Pop(sha1);
    CleanupStack::PushL(hmac);    
    
    HBufC8* A = HBufC8::NewLC(Max(aSeed.Length(), hmac->HashSize())); // simulate the "A" array from the rfc
    HBufC8* msg = HBufC8::NewLC(hmac->HashSize() + aSeed.Length());
    
    TInt generated = 0;    
    A->Des() = aSeed;    
    while (generated < aLength)
    {
        hmac->Reset();
        A->Des() = hmac->Hash(*A);
        msg->Des() = *A;
        msg->Des().Append(aSeed);
        
        TInt length = Min(aLength - generated, hmac->HashSize());
        
        hmac->Reset();        
        output->Des().Append(hmac->Hash(*msg).Left(length));
        
        generated += length;
    }
    
    CleanupStack::PopAndDestroy(msg);
    CleanupStack::PopAndDestroy(A);
    CleanupStack::PopAndDestroy(hmac);    
    CleanupStack::Pop(output);
    
    return output;
}

EXPORT_C HBufC8* SenCryptoUtils::EncodeBase64L(const TDesC8& aData)
{
    if (aData.Length() == 0)
        {
        return NULL;
        }

    TInt remainder = aData.Length() % KToBase64CoefficientNominative;
    TInt length = aData.Length() * KToBase64CoefficientNumerator;
    length /= KToBase64CoefficientNominative;
    if (remainder)
        {
        length++;
        length += KToBase64CoefficientNominative - remainder;
        }

    HBufC8* buffer = HBufC8::NewLC(length);
    
    
    TImCodecB64 base64Codec;
    base64Codec.Initialise();
    TPtr8 des = buffer->Des();  // don't blame me, it's the compiler's fault    
    base64Codec.Encode(aData, des);
    
    CleanupStack::Pop(buffer);
    return buffer;
}

EXPORT_C HBufC8* SenCryptoUtils::DecodeBase64L(const TDesC8& aData)
{
    const TUint8 KBase64Fill = '=';

    TInt length = aData.Length();
    if (aData[length-1] == KBase64Fill)
        {
        length--;
        if (aData[length-2] == KBase64Fill)
            {
            length--;
            }
        }
    length *= KToBase64CoefficientNominative;
    length /= KToBase64CoefficientNumerator;
    if (length <= 0)
        {
        return NULL;
        }

    HBufC8* buffer = HBufC8::NewLC(length);

    TImCodecB64 base64Codec;
    base64Codec.Initialise();
    TPtr8 des = buffer->Des();  // don't blame me, it's the compiler's fault    

    base64Codec.Decode(aData, des);

    CleanupStack::Pop(buffer);
    return buffer;    
}

EXPORT_C HBufC8* SenCryptoUtils::RandomAndHashMd5LC()
    {
    HBufC8* hashedRandom = NULL;
    TTime homeTime;
    homeTime.HomeTime();
    TInt64 seed = homeTime.Int64();
    TBuf8<KSenUuidMaxInt64Length> valueBeforeMd5;
    //randomize
    valueBeforeMd5.AppendNum(Math::Rand(seed));
    //hashing
    CMD5* md5HashGen = CMD5::NewL();
    CleanupStack::PushL(md5HashGen);
    TPtrC8 hash = md5HashGen->Hash(valueBeforeMd5);
    hashedRandom = hash.AllocL();
    CleanupStack::PopAndDestroy(md5HashGen);
    CleanupStack::PushL(hashedRandom);
    return hashedRandom;
    }    

EXPORT_C HBufC8* SenCryptoUtils::CreateEncodedBinarySecretL(const TDesC8& aSecret, const TDesC8& aValueType)
    {
    //from MSP guide
    //aSecret "...Contains the Compact mobile security token. The contents should be Base64 encoded and passed as the BinarySecurityToken element in the WS-Security header 
    
    TPtrC8 pSecret(aSecret);
    CSenXmlReader* reader = CSenXmlReader::NewL(KXmlParserMimeType); // use libxml2 sax parser
    CleanupStack::PushL(reader);
    CSenDomFragment* pFragment = CSenDomFragment::NewL();
    CleanupStack::PushL(pFragment);
    pFragment->SetReader(*reader);    
    pFragment->BuildFrom(aSecret);  
    CSenElement& pElement = pFragment->AsElement();
    if (pElement.LocalName() == KBinarySecurityToken
        && (pElement.Namespace()->URI() == KSecuritySchemeXmlNs
        || pElement.Namespace()->URI() == KSecurityXmlNs))
        {
        pSecret.Set(pElement.Content());
        }
    else
        {
        pSecret.Set(aSecret);
        }
    HBufC8* encodedSecurityToken = EncodeBase64L(pSecret);
    CleanupStack::PushL(encodedSecurityToken);
    HBufC8* binarySecurityToken(NULL);
    if (aValueType.Length())
        {
        CSenWsSecurityHeader::BinarySecurityTokenL(*encodedSecurityToken, aValueType, binarySecurityToken);
        }
    else
        {
        CSenWsSecurityHeader::BinarySecurityTokenL(*encodedSecurityToken, binarySecurityToken);
        }
    CleanupStack::PopAndDestroy(encodedSecurityToken);
    CleanupStack::PopAndDestroy(pFragment);
    CleanupStack::PopAndDestroy(reader);
    return binarySecurityToken;
    }

EXPORT_C HBufC8* SenCryptoUtils::GetTimestampL()
	{
	TTime time;
	time.UniversalTime();
	TTimeIntervalSeconds timestamp;
	TTime refTime(KTimeReference);

	time.SecondsFrom(refTime, timestamp);
	HBufC8* pTimestamp = HBufC8::NewL(KInt32Length);
    TPtr8 buf = pTimestamp->Des();
    buf.AppendNum(timestamp.Int());
	return pTimestamp;
	}
EXPORT_C HBufC8* SenCryptoUtils::GetTimestampL(TTime aTime)
    {
    TTimeIntervalSeconds timestamp;
    TTime refTime(KTimeReference);

    aTime.SecondsFrom(refTime, timestamp);
    HBufC8* pTimestamp = HBufC8::NewL(KInt32Length);
    TPtr8 buf = pTimestamp->Des();
    buf.AppendNum(timestamp.Int());
    return pTimestamp;
    }
EXPORT_C HBufC8* SenCryptoUtils::GetRandomNonceL()
	{
	TTime time;
	time.UniversalTime();
	CMD5 *pMD5HashGen = CMD5::NewL();
	CleanupStack::PushL (pMD5HashGen);
    TBuf8<KInt64Length+KInt32Length> valueBeforeHash;
    // Append current system time
    valueBeforeHash.AppendNum(time.Int64());
    // Append random number
    valueBeforeHash.AppendNum(Math::Random()); //TUint32 Random();
	
    // Calculate hash
    TPtrC8 hash (pMD5HashGen->Hash(valueBeforeHash));
    HBufC8* pResult = HBufC8::NewL(hash.Length() * KHexWidth);
    TPtr8 buf = pResult->Des();
    for (TInt i = 0; i < hash.Length(); i++)
        {
        buf.AppendNumFixedWidth(hash[i], EHex, KHexWidth);
        }
    CleanupStack::PopAndDestroy(pMD5HashGen);
    return pResult;
	}
