/*
* Copyright (c) 2002-2005 Nokia Corporation and/or its subsidiary(-ies). 
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








#include <uri8.h>
#include <e32base.h>
#include <http.h>
#include "senhttpchannelimpl.h"
#include "senhttpeventhandler.h"
#include <e32std.h>

#include "sendebug.h"
#include "senlogger.h"

//
// Implementation of class CSenHttpEventHandler
//

void CSenHttpEventHandler::ConstructL()
    {
    }


CSenHttpEventHandler::CSenHttpEventHandler(CSenHttpChannelImpl* aChannel)//,
                                           //RFileLogger* aLog)
    : iHttpChannel(aChannel),
      //iLog(aLog),
      iTries(0)
    {
    }

CSenHttpEventHandler::~CSenHttpEventHandler()
    {
    }

CSenHttpEventHandler* CSenHttpEventHandler::NewLC(
                                                 CSenHttpChannelImpl* aChannel)//,
                                                 //RFileLogger* aLog)
    {
    CSenHttpEventHandler* pNew =
                    new (ELeave) CSenHttpEventHandler(aChannel);//, aLog);
    CleanupStack::PushL(pNew);
    pNew->ConstructL();
    return pNew;
    }

CSenHttpEventHandler* CSenHttpEventHandler::NewL(CSenHttpChannelImpl* aChannel)//,
                                                 //RFileLogger* aLog)
    {
    CSenHttpEventHandler* pNew = NewLC(aChannel);//, aLog);
    CleanupStack::Pop(pNew);
    return pNew;
    }

// ----------------------------------------------------------------------------
// CSenHttpEventHandler::MHFRunL
// Handle Http stack events.
// ----------------------------------------------------------------------------
//
void CSenHttpEventHandler::MHFRunL(RHTTPTransaction aTransaction,
                                   const THTTPEvent& aEvent)
    {
    TLSLOG_FORMAT((KSenHttpChannelLogChannelBase , KMinLogLevel, _L8("CSenHttpEventHandler::MHFRunL( %d )"), aEvent.iStatus));
    if (aEvent.iStatus < 0)
        {
        if (aEvent.iStatus == KErrDisconnected)
            {
            aTransaction.Cancel();
            TRAPD(err, aTransaction.SubmitL());
            if (err != KErrNone)
                {
                iHttpChannel->HandleRunErrorL(aTransaction, err);
                }
            }
        else
            {
            iHttpChannel->SetExplicitIapDefined(EFalse);
            iHttpChannel->HandleRunErrorL(aTransaction, aEvent.iStatus);
            }
        TLSLOG(KSenHttpChannelLogChannelBase , KMinLogLevel,(_L("CSenHttpEventHandler::MHFRunL() returns")));
        return;
        }
		TLSLOG_FORMAT((KSenHttpChannelLogChannelBase , KMinLogLevel, _L8("CSenHttpEventHandler::statuscode( %d )"), aTransaction.Response().StatusCode()));
    switch (aEvent.iStatus)
        {
        case THTTPEvent::EGotResponseHeaders:
        		TLSLOG(KSenHttpChannelLogChannelBase , KMinLogLevel,(_L("CSenHttpEventHandler::MHFRunL() EGotResponseHeaders")));
            iHttpChannel->HandleResponseHeadersL(aTransaction);
            TLSLOG(KSenHttpChannelLogChannelBase , KMinLogLevel,(_L("CSenHttpEventHandler::MHFRunL() EGotResponseHeaders Completed")));
            break;
        case THTTPEvent::EGotResponseBodyData:
        		TLSLOG(KSenHttpChannelLogChannelBase , KMinLogLevel,(_L("CSenHttpEventHandler::MHFRunL() EGotResponseBodyData")));
            iHttpChannel->HandleResponseBodyDataL(aTransaction);
            iTries = 0;
            TLSLOG(KSenHttpChannelLogChannelBase , KMinLogLevel,(_L("CSenHttpEventHandler::MHFRunL() EGotResponseBodyData Completed")));
            break;
        case THTTPEvent::EResponseComplete:
        		TLSLOG(KSenHttpChannelLogChannelBase , KMinLogLevel,(_L("CSenHttpEventHandler::MHFRunL() EResponseComplete")));
            break;
        case THTTPEvent::ESucceeded:
        		TLSLOG(KSenHttpChannelLogChannelBase , KMinLogLevel,(_L("CSenHttpEventHandler::MHFRunL() ESucceeded")));
            iHttpChannel->HandleResponseL(aTransaction);
            TLSLOG(KSenHttpChannelLogChannelBase , KMinLogLevel,(_L("CSenHttpEventHandler::MHFRunL() ESucceeded Completed")));
            break;
        case THTTPEvent::EFailed:
        case THTTPEvent::EMoreDataReceivedThanExpected:
        		TLSLOG(KSenHttpChannelLogChannelBase , KMinLogLevel,(_L("CSenHttpEventHandler::MHFRunL() EMoreDataReceivedThanExpected | EFailed")));
            iHttpChannel->HandleRunErrorL(aTransaction,
                                    aTransaction.Response().StatusCode());
            TLSLOG(KSenHttpChannelLogChannelBase , KMinLogLevel,(_L("CSenHttpEventHandler::MHFRunL() EMoreDataReceivedThanExpected | EFailed Completed")));
            break;
        case THTTPEvent::EUnrecoverableError:
        		TLSLOG(KSenHttpChannelLogChannelBase , KMinLogLevel,(_L("CSenHttpEventHandler::MHFRunL() EUnrecoverableError")));
            iHttpChannel->HandleRunErrorL(aTransaction, KErrNoMemory);
            TLSLOG(KSenHttpChannelLogChannelBase , KMinLogLevel,(_L("CSenHttpEventHandler::MHFRunL() EUnrecoverableError Completed")));
            break;
        case THTTPEvent::ERedirectRequiresConfirmation:
        		TLSLOG(KSenHttpChannelLogChannelBase , KMinLogLevel,(_L("CSenHttpEventHandler::MHFRunL() ERedirectRequiresConfirmation")));
            iHttpChannel->HandleRedirectRequiresConfirmationL(aTransaction);
            TLSLOG(KSenHttpChannelLogChannelBase , KMinLogLevel,(_L("CSenHttpEventHandler::MHFRunL() ERedirectRequiresConfirmation Completed")));
            break;
        case THTTPEvent::ERedirectedPermanently:
        case THTTPEvent::ERedirectedTemporarily:
        case THTTPEvent::EGotResponseTrailerHeaders:
        		TLSLOG(KSenHttpChannelLogChannelBase , KMinLogLevel,(_L("CSenHttpEventHandler::MHFRunL() ERedirectedPermanently | ERedirectedTemporarily | EGotResponseTrailerHeaders")));
            break;// We don't process this event
        default:
        		TLSLOG(KSenHttpChannelLogChannelBase , KMinLogLevel,(_L("CSenHttpEventHandler::MHFRunL() default:")));
            iHttpChannel->HandleRunErrorL(aTransaction, aEvent.iStatus);
            TLSLOG(KSenHttpChannelLogChannelBase , KMinLogLevel,(_L("CSenHttpEventHandler::MHFRunL() default: Completed")));
            break;
        }
    if (aTransaction.Response().StatusCode() == 401 && iTries < 4)
        {
        iTries++;
        aTransaction.SubmitL(); 
        }
    }

TInt CSenHttpEventHandler::MHFRunError(TInt aError,
                                       RHTTPTransaction aTransaction,
                                       const THTTPEvent& /*aEvent*/)
    {
    TLSLOG_FORMAT((KSenHttpChannelLogChannelBase , KMinLogLevel, _L8("CSenHttpEventHandler::MHFRunError( %d )"), aError));
    TRAP_IGNORE( iHttpChannel->HandleRunErrorL(aTransaction, aError); ) 
    return KErrNone;
    }
/*
RFileLogger* CSenHttpEventHandler::Log() const
    {
    return iLog;
    }
*/
// EOF



