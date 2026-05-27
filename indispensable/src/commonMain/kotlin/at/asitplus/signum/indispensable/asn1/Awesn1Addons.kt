package at.asitplus.signum.indispensable.asn1

import at.asitplus.awesn1.Asn1Decodable
import at.asitplus.awesn1.Asn1Encodable
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1PemDecodable
import at.asitplus.awesn1.Asn1PemEncodable

interface ParsedAwesn1Type<out RawType, EncodableTo : Asn1Element> : Asn1Encodable<EncodableTo>
    where RawType : Asn1Encodable<EncodableTo>
{
    val raw: RawType
    override fun encodeToTlv() = raw.encodeToTlv()
}

interface ParsedAwesn1PEMType<out RawType, EncodableTo : Asn1Element> : ParsedAwesn1Type<RawType, EncodableTo>, Asn1PemEncodable<EncodableTo>
    where RawType : Asn1Encodable<EncodableTo>

abstract class ParsedAwesn1TypeCompanion<out TheType, RawType, RawCompanion, DecodableFrom: Asn1Element>
(private val ctor: (RawType)->TheType, private val rawCompanion: RawCompanion)
: Asn1Decodable<DecodableFrom, TheType>
    where TheType : ParsedAwesn1Type<RawType, DecodableFrom>,
          RawType : Asn1Encodable<DecodableFrom>,
          RawCompanion : Asn1Decodable<DecodableFrom, RawType>

{
    override fun doDecode(src: DecodableFrom) = ctor(rawCompanion.doDecode(src))
}

abstract class ParsedAwesn1PEMTypeCompanion<out TheType, RawType, RawCompanion, DecodableFrom: Asn1Element>
    (ctor: (RawType)->TheType, rawCompanion: RawCompanion)
: ParsedAwesn1TypeCompanion<TheType, RawType, RawCompanion, DecodableFrom>(ctor, rawCompanion), Asn1PemDecodable<DecodableFrom, TheType>
    where TheType : ParsedAwesn1PEMType<RawType, DecodableFrom>,
          RawType : Asn1PemEncodable<DecodableFrom>,
          RawCompanion: Asn1PemDecodable<DecodableFrom, RawType>
