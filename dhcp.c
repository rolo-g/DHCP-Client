// Modified DHCP (client) Library for CSE 4352 Project 1 & 2
// Rolando Rosales 1001850424

// DHCP Library
// Jason Losh

//-----------------------------------------------------------------------------
// Hardware Target
//-----------------------------------------------------------------------------

// Target Platform: -
// Target uC:       -
// System Clock:    -

// Hardware configuration:
// -

//-----------------------------------------------------------------------------
// Device includes, defines, and assembler directives
//-----------------------------------------------------------------------------

#include <stdio.h>
#include "dhcp.h"
#include "arp.h"
#include "timer.h"

#define DHCPDISCOVER 1
#define DHCPOFFER    2
#define DHCPREQUEST  3
#define DHCPDECLINE  4
#define DHCPACK      5
#define DHCPNAK      6
#define DHCPRELEASE  7
#define DHCPINFORM   8

#define DHCP_DISABLED   0
#define DHCP_INIT       1
#define DHCP_SELECTING  2
#define DHCP_REQUESTING 3
#define DHCP_TESTING_IP 4
#define DHCP_BOUND      5
#define DHCP_RENEWING   6
#define DHCP_REBINDING  7
#define DHCP_INITREBOOT 8 // not used since ip not stored over reboot
#define DHCP_REBOOTING  9 // not used since ip not stored over reboot

#define MAX_PACKET_SIZE 1518

// ------------------------------------------------------------------------------
//  Globals
// ------------------------------------------------------------------------------

uint32_t xid = 0x07900000;
uint32_t leaseSeconds = 0;
uint32_t leaseT1 = 0;
uint32_t leaseT2 = 0;

// use these variables if you want
bool discoverNeeded = true;
bool requestNeeded = true;
bool releaseNeeded = true;

bool ipConflictDetectionMode = true;

uint8_t dhcpOfferedIpAdd[4];
uint8_t dhcpServerIpAdd[4];

uint8_t dhcpState = DHCP_INIT;
bool    dhcpEnabled = true;

// ------------------------------------------------------------------------------
//  Structures
// ------------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// Subroutines
//-----------------------------------------------------------------------------

// State functions

void setDhcpState(uint8_t state)
{
    dhcpState = state;
}

uint8_t getDhcpState()
{
    return dhcpState;
}

// New address functions
// Manually requested at start-up
// Discover messages sent every 15 seconds

void callbackDhcpGetNewAddressTimer()
{
}

void requestDhcpNewAddress()
{
}

// Renew functions

void renewDhcp()
{ 
}

void callbackDhcpT1PeriodicTimer()
{
}

void callbackDhcpT1HitTimer()
{
}

// Rebind functions

void rebindDhcp()
{
}

void callbackDhcpT2PeriodicTimer()
{
}

void callbackDhcpT2HitTimer()
{
}

// End of lease timer
void callbackDhcpLeaseEndTimer()
{
}

// Release functions

void releaseDhcp()
{
}

// IP conflict detection

void callbackDhcpIpConflictWindow()
{
    setDhcpState(DHCP_BOUND);
}

void requestDhcpIpConflictTest()
{
    // send the ARP message and starts timer
    startOneshotTimer(callbackDhcpIpConflictWindow, 5);
    setDhcpState(DHCP_TESTING_IP);
}

// TODO: Everything
bool isDhcpIpConflictDetectionMode()
{
    return ipConflictDetectionMode;
}

// Lease functions

// TODO: Everything
uint32_t getDhcpLeaseSeconds()
{
    return leaseSeconds;
}

// Determines whether packet is DHCP
// Must be a UDP packet
bool isDhcpResponse(etherHeader* ether)
{
    bool ok;
    return ok;
}

// Send DHCP message
void sendDhcpMessage(etherHeader *ether, uint8_t type)
{
    uint8_t i;
    uint32_t sum;
    uint16_t tmp16;
    uint16_t dhcpLength;
    uint8_t *optionsPtr;
    uint8_t localHwAddress[6];
    uint8_t localIpAddress[4];

    // Ether frame
    getEtherMacAddress(localHwAddress);
    getIpAddress(localIpAddress);
    for (i = 0; i < HW_ADD_LENGTH; i++)
    {
        ether->destAddress[i] = 0xFF;
        ether->sourceAddress[i] = localHwAddress[i];
    }
    ether->frameType = htons(TYPE_IP);

    // IP header
    ipHeader* ip = (ipHeader*)ether->data;
    ip->rev = 0x4;
    ip->size = 0x5;
    ip->typeOfService = 0;
    ip->id = 0;
    ip->flagsAndOffset = 0;
    ip->ttl = 128;
    ip->protocol = PROTOCOL_UDP;
    ip->headerChecksum = 0;
    for (i = 0; i < IP_ADD_LENGTH; i++)
    {
        ip->destIp[i] = 0xFF;
        ip->sourceIp[i] = 0;
    }
    uint8_t ipHeaderLength = ip->size * 4;

    // UDP header
    udpHeader* udp = (udpHeader*)((uint8_t*)ip + (ip->size * 4));
    udp->sourcePort = htons(68);
    udp->destPort = htons(67);

    // DHCP Frame
    // Using wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol#Operation
    dhcpFrame* dhcp = (dhcpFrame*)udp->data;
    optionsPtr = dhcp->options;

    // These are  the fields common to all DHCP messages (so far... )
    dhcp->op = 0x1;     // Boot Request
    dhcp->htype = 0x1;  // Ethernet
    dhcp->hlen = 0x6;   // MAC length
    dhcp->hops = 0x0;   // Hops
    dhcp->secs = htons(0x0);  // Seconds
    dhcp->flags = htons(0x0); // Flags
    for (i = 0; i < HW_ADD_LENGTH; i++)
    {
        dhcp->chaddr[i] = localHwAddress[i];    // Client MAC Address
    }

    dhcp->magicCookie = htonl(0x63825363);  // Magic Cookie

    switch (type)
    {
        case DHCPDISCOVER:
            xid++;
            dhcp->xid = htonl(xid); // Transaction ID

            for (i = 0; i < IP_ADD_LENGTH; i++)
            {
                dhcp->ciaddr[i] = 0x0;  // Client IP
                dhcp->yiaddr[i] = 0x0;  // Your IP
                dhcp->siaddr[i] = 0x0;  // Server IP
                dhcp->giaddr[i] = 0x0;  // Gateway IP
            }

            // DHCP Data
            for (i = 0; i < 192; i++)
            {
                dhcp->data[i] = 0x0;
            }

            // Writing the options field
            *(optionsPtr++) = 0x35; // Option: (53) DHCP Message Type
            *(optionsPtr++) = 0x1;  // Length: 1
            *(optionsPtr++) = 0x1;  // DHCP: Discover (1)

            *optionsPtr = 0xFF;     // Option End: 255

            setDhcpState(DHCP_SELECTING);

            break;
        case DHCPREQUEST:
            dhcp->xid = htonl(xid); // Transaction ID

            /*
            // Store the offered IP address
            for (i = 0; i < IP_ADD_LENGTH; i++)
            {
                dhcpOfferedIpAdd[i] = dhcp->yiaddr[i];
            }
            */

            // Store the server IP address
            uint8_t *tempServerIpAddPtr = getDhcpOption(ether, 0x36, NULL);

            for (i = 0; i < IP_ADD_LENGTH; i++)
            {
                dhcp->ciaddr[i] = 0x0;  // Client IP
                dhcp->yiaddr[i] = 0x0;  // Your IP

                dhcpServerIpAdd[i] = *tempServerIpAddPtr;
                dhcp->siaddr[i] = dhcpServerIpAdd[i];  // Server IP
                tempServerIpAddPtr++;

                dhcp->giaddr[i] = 0x0;  // Gateway IP
            }

            // DHCP Data
            for (i = 0; i < 192; i++)
            {
                dhcp->data[i] = 0x0;
            }

            // Writing the options field
            *(optionsPtr++) = 0x35; // Option: (53) DHCP Message Type
            *(optionsPtr++) = 0x1;  // Length: 1
            *(optionsPtr++) = 0x3;  // DHCP: Request (3)

            *(optionsPtr++) = 0x32; // Option: (50) Requested IP Address
            *(optionsPtr++) = 0x4;  // Length: 4
            for (i = 0; i < IP_ADD_LENGTH; i++)
            {
                *(optionsPtr++) = dhcpOfferedIpAdd[i];
            }

            *(optionsPtr++) = 0x36; // Option: (54) DHCP Server Identifier
            *(optionsPtr++) = 0x4;  // Length: 4
            for (i = 0; i < IP_ADD_LENGTH; i++)
            {
                *(optionsPtr++) = dhcpServerIpAdd[i];
            }

            *optionsPtr = 0xFF;     // Option End: 255

            setDhcpState(DHCP_REQUESTING);

            break;
        case DHCPDECLINE:
            // TODO: Add code
            break;
        case DHCPRELEASE:
            // TODO: Add code
            break;
        case DHCPINFORM:
            // TODO: Add code
            break;
        default:
            break;
    }

    // adjust lengths
    dhcpLength = sizeof(udpHeader) + sizeof(dhcpFrame) + sizeof(uint8_t)*((optionsPtr + 1) - dhcp->options);
    ip->length = htons(ipHeaderLength + dhcpLength);

    // 32-bit sum over ip header
    calcIpChecksum(ip);
    
    // set udp length
    udp->length = htons(dhcpLength);

    // 32-bit sum over pseudo-header
    sum = 0;
    sumIpWords(ip->sourceIp, 8, &sum);
    tmp16 = ip->protocol;
    sum += (tmp16 & 0xff) << 8;
    sumIpWords(&udp->length, 2, &sum);

    // add udp header
    udp->check = 0;
    sumIpWords(udp, dhcpLength, &sum);
    udp->check = getIpChecksum(sum);

    // send packet with size = ether + udp hdr + ip header + udp_size
    putEtherPacket(ether, sizeof(etherHeader) + ipHeaderLength + dhcpLength);
}

// very complicated and difficult function
uint8_t* getDhcpOption(etherHeader *ether, uint8_t option, uint8_t* length)
{
    uint8_t *optionPtr = (uint8_t*)ether + 282; // start of options field
    uint8_t tempLen = 0; // used to skip over unwanted options

    while (*optionPtr != 0xFF) // while DHCP: End (0xFF) not found
    {
        if (*optionPtr == option)
        {
            *length = *(optionPtr + 1); // not sure why this has a warning
            return optionPtr + 2; // returns the start of the option data
        }
        else
        {
            optionPtr++; // points to the length field
            tempLen = *optionPtr; // sets value of length

            optionPtr += tempLen + 1; // offsets option ptr by lengh + 1
        }
    }
    return 0;
}

// Determines whether packet is DHCP offer response to DHCP discover
// Must be a UDP packet
// TODO: Add more checks
bool isDhcpOffer(etherHeader *ether, uint8_t ipOfferedAdd[])
{
    // these two directly point to the src and dst values of the udp packet
    uint16_t src = ntohs(*(uint16_t *)((uint8_t *)ether + 34));
    uint16_t dst = ntohs(*(uint16_t *)((uint8_t *)ether + 36));

    // makes sure that src and dst are vlaid, and that dhcp message type is 2
    if ((src == 67) && (dst == 68) && (*getDhcpOption(ether, 0x35, NULL) == 2))
    {
        uint8_t i;
        // Store the offered IP address
        for (i = 0; i < IP_ADD_LENGTH; i++)
        {
            dhcpOfferedIpAdd[i] = *(uint8_t *)((uint8_t *)ether + 58 + i);
        }
        return true;
    }
    else
        return false;
}

// Determines whether packet is DHCP ACK response to DHCP request
// Must be a UDP packet
bool isDhcpAck(etherHeader *ether)
{
    if (*getDhcpOption(ether, 0x35, NULL) == 3)
        return true;
    else
        return false;
}

// Handle a DHCP ACK
// TODO: Record remaining stuff
void handleDhcpAck(etherHeader *ether)
{
    // Records IP address, lease time, and server IP address

    setDhcpState(DHCP_BOUND);
}

// Message requests

bool isDhcpDiscoverNeeded()
{
    return discoverNeeded;
}

bool isDhcpRequestNeeded()
{
    return requestNeeded;
}

bool isDhcpReleaseNeeded()
{
    return releaseNeeded;
}

// TODO: Finish all states
void sendDhcpPendingMessages(etherHeader *ether)
{
    switch (dhcpState)
    {
        case DHCP_INIT:
            // if timer hasn't hit 15 seconds again
            if (isDhcpDiscoverNeeded())
            {
                sendDhcpMessage(ether, DHCPDISCOVER);
            }
            break;
        case DHCP_SELECTING:
            // if timer something
            if (isDhcpRequestNeeded())
            {
                getEtherPacket(ether, MAX_PACKET_SIZE);
                if(isDhcpOffer(ether, dhcpOfferedIpAdd))
                {
                    sendDhcpMessage(ether, DHCPREQUEST);
                }
            }
            break;
        case DHCP_REQUESTING:
            getEtherPacket(ether, MAX_PACKET_SIZE);
            if(isDhcpAck(ether))
            {
                handleDhcpAck(ether);
                if(isDhcpIpConflictDetectionMode())
                {
                    // sends ARP response to offered address
                    uint8_t blankIp[4] = {0, 0, 0, 0};
                    sendArpRequest(ether, blankIp, dhcpOfferedIpAdd);
                    // starts the ip conflict test
                    requestDhcpIpConflictTest();
                }
                else
                {
                    // immediately go to bound state if no detection needed
                    setDhcpState(DHCP_BOUND);
                }
            }
            break;
        case DHCP_TESTING_IP:
            getEtherPacket(ether, MAX_PACKET_SIZE);
            if (isArpResponse(ether));
            {
                processDhcpArpResponse(ether);
            }
            break;
        case DHCP_BOUND:
            (*((volatile uint32_t *)0x400253FC)) |= 0x04;
            while(1);
            break;
        case DHCP_RENEWING:
            break;
        case DHCP_REBINDING:

        default:
            break;
    
    }
}

// TODO: Everything
void processDhcpResponse(etherHeader *ether)
{
}

// TODO: Everything
void processDhcpArpResponse(etherHeader *ether)
{
    // this will clear offer and send a decline message
}

// DHCP control functions

void enableDhcp()
{
    dhcpEnabled = true;
}

void disableDhcp()
{
    dhcpEnabled = true;
}

bool isDhcpEnabled()
{
    return dhcpEnabled;
}

