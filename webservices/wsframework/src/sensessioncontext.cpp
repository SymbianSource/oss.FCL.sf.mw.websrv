/*
* Copyright (c) 2002-2007 Nokia Corporation and/or its subsidiary(-ies). 
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








// INCLUDE FILES
#include "sensessioncontext.h" 

EXPORT_C CSenSessionContext* CSenSessionContext::NewL()
    {
    CSenSessionContext* pNew = CSenSessionContext::NewLC();
    CleanupStack::Pop();
    return pNew;
    }

EXPORT_C CSenSessionContext* CSenSessionContext::NewLC()
    {
    CSenSessionContext* pNew = new (ELeave) CSenSessionContext();
    CleanupStack::PushL(pNew);
    pNew->BaseConstructL();
    return pNew;
    }

EXPORT_C CSenSessionContext::CSenSessionContext()
    {
    }

EXPORT_C CSenSessionContext::~CSenSessionContext()
    {
    }
       
EXPORT_C void CSenSessionContext::BaseConstructL()
    {
//    CSenContext::BaseConstructL();
    }

// From MSenSessionContext:
/*
SenContext::TContextType CSenSessionContext::Type() const
    {
    return SenContext::EMessageContext;
    }
       
SenContext::TContextDirection CSenSessionContext::Direction() const
    {
    return CSenContext::Direction();
    }
       
TInt CSenSessionContext::Add(const TDesC8& aKey, const TDesC8& aValue)
    {
    return CSenContext::Add( aKey, aValue );
    }
       
TInt CSenSessionContext::Update(const TDesC8& aKey, const TDesC8& aValue)
    {
    return CSenContext::Update( aKey, aValue );
    }
       
const TDesC8* CSenSessionContext::GetDesC8L(const TDesC8& aKey)
    {
    return CSenContext::GetDesC8L( aKey );
    }
       
TInt CSenSessionContext::Add(const TDesC8& aKey, TInt aValue)
    {
    return CSenContext::Add( aKey, aValue );
    }
       
TInt CSenSessionContext::Update(const TDesC8& aKey, TInt aValue)
    {
    return CSenContext::Update( aKey, aValue );
    }
       
const TInt* CSenSessionContext::GetIntL(const TDesC8& aKey)
    {
    return CSenContext::GetIntL( aKey );
    }
       
TInt CSenSessionContext::Add(const TDesC8& aKey, CSenElement* aValue)
    {
    return CSenContext::Add( aKey, aValue );
    }
       
TInt CSenSessionContext::Update(const TDesC8& aKey, CSenElement* aValue)
    {
    return CSenContext::Update( aKey, aValue );
    }
       
const CSenElement* CSenSessionContext::GetSenElementL(const TDesC8& aKey)
    {
    return CSenContext::GetSenElementL( aKey );
    }
       
TInt CSenSessionContext::Add(const TDesC8& aKey, TAny* aValue)
    {
    return CSenContext::Add( aKey, aValue );
    }
       
TInt CSenSessionContext::Update(const TDesC8& aKey, TAny* aValue)
    {
    return CSenContext::Update( aKey, aValue );
    }
       
TAny* CSenSessionContext::GetAny(const TDesC8& aKey)
    {
    return CSenContext::GetAny( aKey );
    }
       
TInt CSenSessionContext::Remove(const TDesC8& aKey) 
    {
    return CSenContext::Remove(aKey);
    }

TInt CSenSessionContext::Count() const
    {
    return CSenContext::Count();
    }

TPtrC8 CSenSessionContext::KeyAtL(TInt aIndex)
    {
    return CSenContext::KeyAtL(aIndex);
    }

void CSenSessionContext::Reset()
    {
    CSenContext::Reset();
    }
    
CSenSoapMessage* CSenSessionContext::GetCurrentSoapMessage() // DEPRECATED: 
    {
    CSenSoapMessage* pSoapMessage = NULL;
    
    TInt index = iItems.Find( KSenCtxKeyCurrentSoapMessage );
    if ( index != KErrNotFound )
        {
        const CSenContextItem* pItem = iItems.ValueAt(index);
        pSoapMessage = &(pItem->ToSenSoapMessageL());
        }
    return pSoapMessage;
    }
    
TPtrC8 CSenSessionContext::GetMessage()
    {
    TInt index = iItems.Find( KSenCtxKeyCurrentMessageAsDesc );
    if ( index != KErrNotFound )
        {
        const CSenContextItem* pItem = iItems.ValueAt(index);
        const TDesC8* desc = pItem->ToDesC8L();
        return *desc;
        }
    return KNullDesC8();
    }
    
TInt CSenSessionContext::Add(const TDesC8& aKey, CSenSoapEnvelope* aValue)
    {
    return CSenContext::Add( aKey, aValue );    
    }
    
TInt CSenSessionContext::Update(const TDesC8& aKey, CSenSoapEnvelope* aValue)
    {
    return CSenContext::Update( aKey, aValue );
    }
    
const CSenSoapEnvelope* CSenSessionContext::GetSenSoapEnvelopeL(const TDesC8& aKey)
    {
    TInt index = iItems.Find( aKey );
    if ( index != KErrNotFound )
        {
        const CSenContextItem* pItem = iItems.ValueAt(index);
        const CSenSoapEnvelope* envelope = ((CSenSoapEnvelope*)&(pItem->ToSenSoapMessageL()));
        return envelope;
        }
    return NULL;
    }
    
MSenMessage* CSenSessionContext::Message()
    {
    TInt index = iItems.Find( KSenCtxKeyMessage );
    if ( index != KErrNotFound )
        {
        const CSenContextItem* pItem = iItems.ValueAt(index);
        return ((MSenMessage*)&(pItem->ToSenMessageL()));
        }
    return NULL;
    }
    
TInt CSenSessionContext::SetMessage(MSenMessage* apMessage, TBool aOwned)
    {
    TInt leaveCode(KErrNone);
    CSenContextItem* pItem = MessageToItem( apMessage, aOwned, leaveCode );

    if( leaveCode != KErrNone ) 
        {
        delete pItem; // should ALWAYS be NULL(!)
        return leaveCode;
        }
        
    TInt retCode(iItems.UpdateValue(&KSenCtxKeyMessage(), pItem));
    if( retCode != KErrNone && aOwned )
        {
        delete pItem; // delete the orphan item
        } 
    return retCode;
    }
    
    
CSenChunk* CSenSessionContext::Chunk()
    {
    TInt index = iItems.Find( KSenCtxKeyChunk );
    if ( index != KErrNotFound )
        {
        const CSenContextItem* pItem = iItems.ValueAt(index);
        return ((CSenChunk*)&(pItem->ToSenChunkL()));
        }
    return NULL;
    }
    
TInt CSenSessionContext::SetChunk(CSenChunk* apMsgAsChunk, TBool aOwned)
    {
    TInt leaveCode(KErrNone);
    
    CSenContextItem* pItem = NULL;
    if( aOwned )
        {
        TRAP( leaveCode, pItem = CSenContextItem::NewL(apMsgAsChunk); )
        }
    else // chunk is not to be owned
        {
        TRAP( leaveCode, pItem = CSenContextItem::NewL(*apMsgAsChunk); )
        }

    if( leaveCode != KErrNone ) 
        {
        delete pItem; // should ALWAYS be NULL(!)
        return leaveCode;
        }
        
    TInt retCode(iItems.UpdateValue(&KSenCtxKeyChunk(), pItem));
    if( retCode != KErrNone && aOwned )
        {
        delete pItem; // delete the orphan item
        } 
    return retCode;
    }
    

TInt CSenSessionContext::SetProperties(MSenProperties* apProperties, TBool aOwned)
    {
    if( !apProperties )
        {
        return KErrArgument;
        }
        
    TInt retCode(KErrNone);
    if ( aOwned )
        {
        delete ipOwnedTp;
        ipOwnedTp = NULL;
        ipOwnedTp = apProperties;
        }
    else
        {
        
        CSenContextItem* pItem = NULL;
        TInt leaveCode(KErrNone);
//        if( aOwned )
//            {
//            TRAP( leaveCode, pItem = CSenContextItem::NewL(apProperties); )
//            }
//        else // chunk is not to be owned
//            {
            TRAP( leaveCode, pItem = CSenContextItem::NewL(*apProperties); )
//            }

        if( leaveCode != KErrNone ) 
            {
            delete pItem; // should ALWAYS be NULL(!)
            return leaveCode;
            }
            
        retCode = iItems.UpdateValue(&KSenCtxKeyChunk(), pItem);
        if( retCode != KErrNone && aOwned )
            {
            delete pItem; // delete the orphan item
            } 
        }
    return retCode;
    }


MSenProperties* CSenSessionContext::Properties()
    {
    if( ipOwnedTp )
        {
        return ipOwnedTp;
        }
    else
        {
        TInt index = iItems.Find( KSenCtxKeyMessageProperties );
        if ( index != KErrNotFound )
            {
            const CSenContextItem* pItem = iItems.ValueAt(index);
            if( pItem->Type() == MSenContextItem::EMSenProperties )
                {
                MSenProperties* pProperties = (MSenProperties*)pItem;
                return pProperties;
                }
            }
        return NULL;
        }
    }

// Method for adding an "intermediate" message behind certain key; used normally to conduct final "service message"
TInt CSenSessionContext::Add(const TDesC8& aKey, MSenMessage* apMessage, TBool aOwned)
    {
    if( iItems.Count() > 0 && iItems.Find(aKey) != KErrNotFound )
        {
        return KErrAlreadyExists;
        }

    TInt leaveCode(KErrNone);
    CSenContextItem* pItem = MessageToItem( apMessage, aOwned, leaveCode );
    if( leaveCode != KErrNone ) 
        {
        return leaveCode;
        }

    TInt retCode(iItems.Append(&aKey, pItem));
    if( retCode != KErrNone )
        {
        delete pItem;
        }
    return retCode;
    }
    
// Method for updating some "intermediate" message behind certain key; used normally to conduct final "service message"    
TInt CSenSessionContext::Update(const TDesC8& aKey, MSenMessage* apMessage, TBool aOwned)
    {
    TInt leaveCode(KErrNone);
    CSenContextItem* pItem = MessageToItem( apMessage, aOwned, leaveCode );
    if( leaveCode != KErrNone ) 
        {
        return leaveCode;
        }

    TInt retCode(iItems.UpdateValue(&aKey, pItem));
    if( retCode != KErrNone && aOwned )
        {
        delete pItem;
        }
    return retCode;    
    }
    
// Method for getting "intermediate" message behind certain key; used normally to conduct final "service message"    
MSenMessage* CSenSessionContext::GetMessage(const TDesC8& aKey)
    {
    TInt index = iItems.Find(aKey);
    if ( index != KErrNotFound )
        {
        const CSenContextItem* pItem = iItems.ValueAt(index);
        if(pItem)
            {
            return &pItem->ToSenMessageL();
            }
        }
    return NULL;    
    }
 
// private helper method(s):
CSenContextItem* CSenSessionContext::MessageToItem(MSenMessage* apMessage, TBool aOwned, TInt& aError)
    {
    aError = KErrNone;
    CSenContextItem* pItem = NULL;
    if( aOwned )
        {
        if( apMessage->IsSafeToCast( MSenMessage::EMessageBase ) )
            {
            CSenMessageBase* msgBase = (CSenMessageBase*) apMessage;
            TRAP( aError, pItem = CSenContextItem::NewL( msgBase ); )
            }
        else if ( apMessage->IsSafeToCast( MSenMessage::ESoapEnvelope2 ) )
            {
            CSenSoapEnvelope2* msgSoap2 = (CSenSoapEnvelope2*) apMessage;
            TRAP( aError,  pItem = CSenContextItem::NewL( msgSoap2 ); )
            }
        else 
            {
            aError = KErrNotSupported;
            return NULL;
            }
        }
    else // provided message is *not to be owned*
        {
        TRAP( aError, pItem = CSenContextItem::NewL(*apMessage); )
        }
    return pItem;        
    } 
    
TInt CSenSessionContext::SetDirection( SenContext::TContextDirection aDirection )
    {
    CSenContext::SetDirection( aDirection );
    return KErrNone;
    }

const CSenXmlReader* CSenSessionContext::GetParser()
    {
    return CSenContext::GetParser();
    }
*/       
// End of file

