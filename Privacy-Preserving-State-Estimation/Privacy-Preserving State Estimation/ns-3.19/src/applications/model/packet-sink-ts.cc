/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright 2007 University of Washington
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author:  Tom Henderson (tomhend@u.washington.edu)
 */
#include "ns3/address.h"
#include "ns3/address-utils.h"
#include "ns3/log.h"
#include "ns3/inet-socket-address.h"
#include "ns3/inet6-socket-address.h"
#include "ns3/node.h"
#include "ns3/socket.h"
#include "ns3/udp-socket.h"
#include "ns3/simulator.h"
#include "ns3/socket-factory.h"
#include "ns3/packet.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/packet-sink-ts.h"
#include "ns3/seq-ts-header.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("PacketSinkTs");
NS_OBJECT_ENSURE_REGISTERED (PacketSinkTs);

TypeId 
PacketSinkTs::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::PacketSinkTs")
    .SetParent<Application> ()
    .AddConstructor<PacketSinkTs> ()
    .AddAttribute ("Local", "The Address on which to Bind the rx socket.",
                   AddressValue (),
                   MakeAddressAccessor (&PacketSinkTs::m_local),
                   MakeAddressChecker ())
    .AddAttribute ("Protocol", "The type id of the protocol to use for the rx socket.",
                   TypeIdValue (UdpSocketFactory::GetTypeId ()),
                   MakeTypeIdAccessor (&PacketSinkTs::m_tid),
                   MakeTypeIdChecker ())
    .AddTraceSource ("Rx", "A packet has been received",
                     MakeTraceSourceAccessor (&PacketSinkTs::m_rxTrace))
  ;
  return tid;
}

PacketSinkTs::PacketSinkTs ()
{
  NS_LOG_FUNCTION (this);
  m_socket = 0;
  m_totalRx = 0;
  
  //Decryptor = CryptoPP::ECIES < ECC_ALGORITHM >::Decryptor (prng, ECC_CURVE); //ECIES
  
  /*privateKey.Initialize (prng, ECC_CURVE);    
  privateKey.MakePublicKey (publicKey);*/
}

PacketSinkTs::~PacketSinkTs()
{
  NS_LOG_FUNCTION (this);
}

uint32_t PacketSinkTs::GetTotalRx () const
{
  NS_LOG_FUNCTION (this);
  return m_totalRx;
}

Ptr<Socket>
PacketSinkTs::GetListeningSocket (void) const
{
  NS_LOG_FUNCTION (this);
  return m_socket;
}

std::list<Ptr<Socket> >
PacketSinkTs::GetAcceptedSockets (void) const
{
  NS_LOG_FUNCTION (this);
  return m_socketList;
}

void PacketSinkTs::DoDispose (void)
{
  NS_LOG_FUNCTION (this);
  m_socket = 0;
  m_socketList.clear ();

  // chain up
  Application::DoDispose ();
}


// Application Methods
void PacketSinkTs::StartApplication ()    // Called at time specified by Start
{
  NS_LOG_FUNCTION (this);
  // Create the socket if not already
  if (!m_socket)
    {
      m_socket = Socket::CreateSocket (GetNode (), m_tid);
      m_socket->Bind (m_local);
      m_socket->Listen ();
      m_socket->ShutdownSend ();
      if (addressUtils::IsMulticast (m_local))
        {
          Ptr<UdpSocket> udpSocket = DynamicCast<UdpSocket> (m_socket);
          if (udpSocket)
            {
              // equivalent to setsockopt (MCAST_JOIN_GROUP)
              udpSocket->MulticastJoinGroup (0, m_local);
            }
          else
            {
              NS_FATAL_ERROR ("Error: joining multicast on a non-UDP socket");
            }
        }
    }

  m_socket->SetRecvCallback (MakeCallback (&PacketSinkTs::HandleRead, this));
  m_socket->SetAcceptCallback (
    MakeNullCallback<bool, Ptr<Socket>, const Address &> (),
    MakeCallback (&PacketSinkTs::HandleAccept, this));
  m_socket->SetCloseCallbacks (
    MakeCallback (&PacketSinkTs::HandlePeerClose, this),
    MakeCallback (&PacketSinkTs::HandlePeerError, this));
}

void PacketSinkTs::StopApplication ()     // Called at time specified by Stop
{
  NS_LOG_FUNCTION (this);
  while(!m_socketList.empty ()) //these are accepted sockets, close them
    {
      Ptr<Socket> acceptedSocket = m_socketList.front ();
      m_socketList.pop_front ();
      acceptedSocket->Close ();
    }
  if (m_socket) 
    {
      m_socket->Close ();
      m_socket->SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
    }
}

void PacketSinkTs::HandleRead (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  Ptr<Packet> packet;
  Address from;
  
  size_t packetSize;
  byte* signature;
  byte* plainText;
  
  //byte *cipherText;   //ECIES & ECDSA
  //byte *cipherText;
  
  while ((packet = socket->RecvFrom (from)))
    {
      if (packet->GetSize () == 0)
        { //EOF
          break;
        }
      //packetSize = packet->GetSize ();
      m_totalRx += packet->GetSize ();
      uint32_t m_rxBytes = packet->GetSize ();
      m_rxTrace (packet, from);
      
      SeqTsHeader seqTs;
      packet->PeekHeader (seqTs);
      
      //int recoveredTextLength = sizeof(int) + sizeof (uint64_t);  //ECIES
      //byte * recoveredText = (byte *)malloc(recoveredTextLength); //ECIES
      //size_t cipherTextLength = Decryptor.CiphertextLength (recoveredTextLength); // ECIES
      
      //cipherText = new uint8_t [packet->GetSize ()];  //ECIES & ECDSA
      
      //cipherText = new uint8_t [packet->GetSize ()];
      
      packetSize = packet->GetSize();
      
      
      
      // Decryption
      //Decryptor.Decrypt (prng, cipherText, cipherTextLength, recoveredText);      //ECIES
      
      size_t plainTextLength = sizeof(int) + sizeof(uint64_t);
      size_t signatureLength = packetSize - plainTextLength;
      
      plainText = (byte *)malloc(plainTextLength);
      signature = (byte *)malloc(signatureLength);
      
      memset (plainText, 0xFB, plainTextLength);
      memset (signature, 0xFB, signatureLength);
      
      CryptoPP::ECDSA<ECC_ALGORITHM, SHA1>::Verifier Verifier (publicKey);
      
      //Verifier.VerifyMessage(plainText, plainTextLength, signature, signatureLength);
      
      NS_LOG_INFO("RECEIVING SIZE : "<< packetSize); 
      
     /// SeqTsHeader seqTs;
    //  packet->PeekHeader (seqTs);
      ///packet->RemoveHeader (seqTs);
      
      if (InetSocketAddress::IsMatchingType (from))
        {
              Time now = Simulator::Now ();
              NS_LOG_INFO (" RX " << m_rxBytes 
                           << " From "<< InetSocketAddress::ConvertFrom (from).GetIpv4 () 
         ///                  << " Sequence Number: " << seqTs.GetSeq () 
                           << " Uid: " << packet->GetUid () 
                           << " TXtime: " << seqTs.GetTs () 
                           << " RXtime: " << now );
            //               << " Delay: " << (now - seqTs.GetTs ()));
         // NS_LOG_INFO ("At time " << Simulator::Now ().GetSeconds ()
         //              << "s packet sink received "
         //              <<  packet->GetSize () << " bytes from "
         //              << InetSocketAddress::ConvertFrom(from).GetIpv4 ()
         //              << " port " << InetSocketAddress::ConvertFrom (from).GetPort ()
         //              << " total Rx " << m_totalRx << " bytes");
        }
      else if (Inet6SocketAddress::IsMatchingType (from))
        {
          NS_LOG_INFO ("TraceDelay: RX " << m_rxBytes <<
                           " bytes from "<< Inet6SocketAddress::ConvertFrom (from).GetIpv6 () <<
                           ///" Sequence Number: " << seqTs.GetSeq() <<
                           " Uid: " << packet->GetUid () <<
                           " TXtime: " << seqTs.GetTs () <<
                           " RXtime: " << Simulator::Now () );
                           //" Delay: " << Simulator::Now () - seqTs.GetTs ());
          /*NS_LOG_INFO ("At time " << Simulator::Now ().GetSeconds ()
                       << "s packet sink received "
                       <<  packet->GetSize () << " bytes from "
                       << Inet6SocketAddress::ConvertFrom(from).GetIpv6 ()
                       << " port " << Inet6SocketAddress::ConvertFrom (from).GetPort ()
                       << " total Rx " << m_totalRx << " bytes"); */
        }
     
    }
}


void PacketSinkTs::HandlePeerClose (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
}
 
void PacketSinkTs::HandlePeerError (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
}
 

void PacketSinkTs::HandleAccept (Ptr<Socket> s, const Address& from)
{
  NS_LOG_FUNCTION (this << s << from);
  s->SetRecvCallback (MakeCallback (&PacketSinkTs::HandleRead, this));
  m_socketList.push_back (s);
}

} // Namespace ns3
