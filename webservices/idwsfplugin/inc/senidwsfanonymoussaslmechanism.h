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
* Description: Header declaration
*
*/








#ifndef SEN_IDWSF_ANONYMOUS_SASL_MECHANISM_H
#define SEN_IDWSF_ANONYMOUS_SASL_MECHANISM_H

// INCLUDES
#include "SenSecurityMechanism.h"
#include "MSenCoreServiceManager.h"

// FORWARD DECLARATIONS
class MSenSaslMessage;

// CLASS DECLARATION
class CSenIdWsfAnonymousSaslMechanism :  public CSenSecurityMechanism
    {
    public: // Constructors and destructor
    
        static CSenIdWsfAnonymousSaslMechanism* NewL(
                                    MSenCoreServiceManager& aServiceManager);
        static CSenIdWsfAnonymousSaslMechanism* NewLC(
                                    MSenCoreServiceManager& aServiceManager);

        // New functions
    
        virtual const TDesC8& Name();
        virtual TInt HandleResponseL(MSenSaslMessage& aResponse,
                                     MSenSaslMessage& aNewRequest);
        
        virtual TBool IsPasswordFromUser();

    protected:
    
        /**
        * C++ default constructor.
        */
        CSenIdWsfAnonymousSaslMechanism(MSenCoreServiceManager& aServiceManager);
    };

#endif // SEN_IDWSF_ANONYMOUS_SASL_MECHANISM_H

// End of File
