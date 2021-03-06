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
* Description: Header declaration
*
*/








#ifndef WSSTAR_ADDRESSING_HEADER_INBOUND_H
#define WSSTAR_ADDRESSING_HEADER_INBOUND_H

#include <e32std.h>


// FORWARD DECLARATIONS

// CONSTANTS


// INCLUDES
#include "SenBaseFragment.h"

#include "senmessagehandler.h"
#include "wsstarmessagehandlerscons.h"
#include "wsstarmessagecontext.h"
#include "SenSoapEnvelope.h"
#include "uri8.h"


const TInt KStateParsingReplyTo = 501;
const TInt KStateParsingFaultTo = 503;
const TInt KStateParsingFrom = 505;

/**
 * Class:       
 *
 * Description: An implementation of the CWSStarHandler definition. This is concrete
 * class, instance of which ECOM framework gives to ECOM clients.
 */
class CWSStarAddressingHeaderInbound : public CSenBaseFragment//, public MWSStarHandlerAddressingHeader
    {
public:
    /**
     * Function:    NewL
     *
     * Description: Create instance of concrete implementation. Note that ECOM
     *              interface implementations can only have two signatures for
     *              NewL:
     *               - NewL without parameters (used here)
     *               - NewL with TAny* pointer, which may provide some client
     *                 data
     *
     * Returns:    Instance of this class.
     *
     * Note:       The interface, which is abstract base class of this
     *             implementation, also provides NewL method. Normally abstract
     *             classes do not provide NewL, because they cannot create
     *             instances of themselves.
     */
    static CWSStarAddressingHeaderInbound* NewL(const TDesC8* aVersion);
    static CWSStarAddressingHeaderInbound* NewLC(const TDesC8* aVersion);


private:
    // From CBaseFragment
    virtual void StartElementL(const TDesC8& aNsUri,
                               const TDesC8& aLocalName,
                               const TDesC8& aQName,
                               const RAttributeArray& aAttributes);
    
    virtual void EndElementL(const TDesC8& aNsUri,
                             const TDesC8& aLocalName,
                             const TDesC8& aQName);

    
public: // destructor
    virtual ~CWSStarAddressingHeaderInbound();


protected:
    /**
     * Function:   CWSStarHandlerAddressingInbound
     *
     * Discussion: Perform the first phase of two phase construction
     */
    CWSStarAddressingHeaderInbound();

    /**
     * Function:   ConstructL
     *
     * Discussion: Perform the second phase construction of a
     *             CImplementationClassPlus object.
     */
    void ConstructL(const TDesC8* aVersion);

public:
    TInt SetMessageContext(MSenMessageContext& aCtx);
    const TDesC8* Version() const;

private:

//data
    MSenMessageContext* iMessageContext; //not owned    
    const TDesC8* iVersion;
    HBufC8* iVersionBuf;
    TBool iDeviceAddress;
    };

#endif // WSSTAR_ADDRESSING_HEADER_INBOUND_H

