/*
* Copyright (c) 2002-2006 Nokia Corporation and/or its subsidiary(-ies). 
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
#include <e32std.h>
#include <ecom/implementationproxy.h>
#include "senhttpchanneltransportplugin.h"

#ifndef RD_SEN_COMPILE_SIS_PACKAGE_FILES
    const TInt32 KHttpChannelTransportPluginUid = 0x10274C74;
#else
    const TInt32 KHttpChannelTransportPluginUid = 0x101F974A;
#endif
// Provides a key value pair table, this is used to identify
// the correct construction function for the requested interface.
const TImplementationProxy ImplementationTable[] =
    {
#ifdef IMPLEMENTATION_PROXY_ENTRY
        IMPLEMENTATION_PROXY_ENTRY(KHttpChannelTransportPluginUid,  CSenHttpChannelTransportPlugin::NewL)
#else
        {{KHttpChannelTransportPluginUid},  CSenHttpChannelTransportPlugin::NewL}
#endif
    };

// Function used to return an instance of the proxy table.
EXPORT_C const TImplementationProxy* ImplementationGroupProxy(TInt& aTableCount)
    {
    aTableCount = sizeof(ImplementationTable) / sizeof(TImplementationProxy);
    return ImplementationTable;
    }

// End of File

