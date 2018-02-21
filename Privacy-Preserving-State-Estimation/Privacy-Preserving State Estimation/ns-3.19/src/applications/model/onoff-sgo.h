/* 
 * File:   onoff-sgo.h
 * Author: samettonyali
 *
 * Created on August 11, 2014, 2:03 PM
 */
/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
//
// Copyright (c) 2006 Georgia Tech Research Corporation
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation;
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//
// Author: George F. Riley<riley@ece.gatech.edu>
//

// ns3 - On/Off Data Source Application class
// George F. Riley, Georgia Tech, Spring 2007
// Adapted from ApplicationOnOff in GTNetS.
#ifndef ONOFF_SGO_H
#define	ONOFF_SGO_H

#include "ns3/address.h"
#include "ns3/application.h"
#include "ns3/event-id.h"
#include "ns3/ptr.h"
#include "ns3/data-rate.h"
#include "ns3/traced-callback.h"

// Crypto++ Includes
#include "cryptopp/cryptlib.h"
#include "cryptopp/oids.h"
#include "cryptopp/osrng.h"
#include "cryptopp/eccrypto.h"
#include "cryptopp/asn.h"
#include "cryptopp/ecp.h"
#include "cryptopp/ec2n.h"
#include "cryptopp/simple.h"
#include "cryptopp/sha.h"
#include "cryptopp/files.h"
#include "cryptopp/filters.h"
#include "cryptopp/modes.h"

#define ECC_ALGORITHM CryptoPP::ECP
#define SHA1 CryptoPP::SHA1
#define ECC_CURVE CryptoPP::ASN1::secp128r1()

namespace ns3 {

class Address;
class RandomVariableStream;
class Socket;

/**
 * \ingroup applications 
 * \defgroup onoff OnOffApplication
 *
 * This traffic generator follows an On/Off pattern: after 
 * Application::StartApplication
 * is called, "On" and "Off" states alternate. The duration of each of
 * these states is determined with the onTime and the offTime random
 * variables. During the "Off" state, no traffic is generated.
 * During the "On" state, cbr traffic is generated. This cbr traffic is
 * characterized by the specified "data rate" and "packet size".
 */
/**
* \ingroup onoff
*
* \brief Generate traffic to a single destination according to an
*        OnOff pattern.
*
* This traffic generator follows an On/Off pattern: after
* Application::StartApplication
* is called, "On" and "Off" states alternate. The duration of each of
* these states is determined with the onTime and the offTime random
* variables. During the "Off" state, no traffic is generated.
* During the "On" state, cbr traffic is generated. This cbr traffic is
* characterized by the specified "data rate" and "packet size".
*
* Note:  When an application is started, the first packet transmission
* occurs _after_ a delay equal to (packet size/bit rate).  Note also,
* when an application transitions into an off state in between packet
* transmissions, the remaining time until when the next transmission
* would have occurred is cached and is used when the application starts
* up again.  Example:  packet size = 1000 bits, bit rate = 500 bits/sec.
* If the application is started at time 3 seconds, the first packet
* transmission will be scheduled for time 5 seconds (3 + 1000/500)
* and subsequent transmissions at 2 second intervals.  If the above
* application were instead stopped at time 4 seconds, and restarted at
* time 5.5 seconds, then the first packet would be sent at time 6.5 seconds,
* because when it was stopped at 4 seconds, there was only 1 second remaining
* until the originally scheduled transmission, and this time remaining
* information is cached and used to schedule the next transmission
* upon restarting.
*
* If the underlying socket type supports broadcast, this application
* will automatically enable the SetAllowBroadcast(true) socket option.
*/
class OnOffSGO : public Application 
{
public:
    
  static TypeId GetTypeId (void);

  OnOffSGO ();

  virtual ~OnOffSGO();

  /**
   * \param maxBytes the total number of bytes to send
   *
   * Set the total number of bytes to send. Once these bytes are sent, no packet 
   * is sent again, even in on state. The value zero means that there is no 
   * limit.
   */
  void SetMaxBytes (uint32_t maxBytes);

  /**
   * \return pointer to associated socket
   */
  Ptr<Socket> GetSocket (void) const;

 /**
  * Assign a fixed random variable stream number to the random variables
  * used by this model.  Return the number of streams (possibly zero) that
  * have been assigned.
  *
  * \param stream first stream index to use
  * \return the number of stream indices assigned by this model
  */
  int64_t AssignStreams (int64_t stream);

protected:
  virtual void DoDispose (void);
private:
  // inherited from Application base class.
  virtual void StartApplication (void);    // Called at time specified by Start
  virtual void StopApplication (void);     // Called at time specified by Stop

  //helpers
  void CancelEvents ();

  void Construct (Ptr<Node> n,
                  const Address &remote,
                  std::string tid,
                  const RandomVariable& ontime,
                  const RandomVariable& offtime,
                  uint32_t size);


  // Event handlers
  void StartSending ();
  void StopSending ();
  void SendPacket ();

  Ptr<Socket>     m_socket;       // Associated socket
  Address         m_peer;         // Peer address
  bool            m_connected;    // True if connected
  Ptr<RandomVariableStream>  m_onTime;       // rng for On Time
  Ptr<RandomVariableStream>  m_offTime;      // rng for Off Time
  DataRate        m_cbrRate;      // Rate that data is generated
  uint32_t        m_pktSize;      // Size of packets
  uint32_t        m_residualBits; // Number of generated, but not sent, bits
  Time            m_lastStartTime; // Time last packet sent
  uint32_t        m_maxBytes;     // Limit total number of bytes sent
  uint32_t        m_totBytes;     // Total bytes sent so far
  EventId         m_startStopEvent;     // Event id for next start or stop event
  EventId         m_sendEvent;    // Eventid of pending "send packet" event
  bool            m_sending;      // True if currently in sending state
  TypeId          m_tid;
  
  TracedCallback<Ptr<const Packet> > m_txTrace;
  
  uint32_t m_seqnum;
  Time            m_firstSent;
  Time            m_interval;
  bool            m_firstTime;
  uint16_t        m_trsmode;
  uint16_t        m_meterSize;

  std::string m_obfsValues;
  
  /*CryptoPP::ECIES < ECC_ALGORITHM >::PrivateKey m_privateKey;
  CryptoPP::ECIES < ECC_ALGORITHM >::PublicKey m_leadKey;
  CryptoPP::ECIES < ECC_ALGORITHM >::Encryptor Encryptor;    
  CryptoPP::ECIES < ECC_ALGORITHM >::Decryptor Decryptor;
  CryptoPP::AutoSeededRandomPool prng;*/
  
  CryptoPP::ECDSA <ECC_ALGORITHM, SHA1>::PrivateKey m_privateKey;
  CryptoPP::AutoSeededRandomPool prng;
//  CryptoPP::ECDSA <ECC_ALGORITHM, SHA1>::Signer signer;

private:
  void ScheduleNextTx ();
  void ScheduleStartEvent ();
  void ScheduleStopEvent ();
  void SetPacketSize(uint8_t size);
  void ConnectionSucceeded (Ptr<Socket> socket);
  void ConnectionFailed (Ptr<Socket> socket);
};

} // namespace ns3

#endif	/* ONOFF_SGO_H */
