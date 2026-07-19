-- SPDM Dissector for MCTP over I2C (SMBus)
-- Based on SPDMwid.lua (SPDM over MCTP over TCP/IPv4)
-- Captured via tcpdump on MCTP I2C interface (LinkType 113 = Linux SLL)
--
-- Usage:
--   wireshark -X lua_script:SPDM-i2c.lua -r capture.pcap
--   or place in ~/.local/lib/wireshark/plugins/

-- SPDM over MCTP over I2C packet structure:
--   [SLL Header (16B)] [MCTP Transport Header] [SPDM Message]
--
-- SLL header: pkttype(2) + arphrd(2) + addrlen(2) + addr(8) + proto(2)
--
-- MCTP Transport Header (DSP0236):
--   Byte 0: [3:0]=HdrVersion, [7:4]=Reserved
--   Byte 1: Destination EID
--   Byte 2: Source EID
--   Byte 3: [7]=SOM, [6]=EOM, [5:4]=PktSeq, [3:0]=MessageTag
--   Byte 4: [7]=IntegrityCheck, [6:0]=HeaderDigest/MessageTag
--   Byte 5: MessageType (0x05 = SPDM)

local proto_mctp_i2c = Proto("MCTP-I2C", "MCTP over I2C (SMBus)")
local proto_spdm = Proto("SPDM", "Security Protocol Data Model")

-- ==========================================================================
-- MCTP fields
-- ==========================================================================

local yesno = {
    [0] = "No",
    [1] = "Yes"
}

local hdr_ver = {
    [0] = "Reserved",
    [1] = "MCTP Base Specification"
}

local msg_types = {
    [0x00] = "MCTP Control",
    [0x01] = "PLDM",
    [0x02] = "PLDM (Reserved)",
    [0x03] = "NC-SI",
    [0x04] = "Ethernet",
    [0x05] = "SPDM",
    [0xFE] = "Vendor Defined (MCTP)",
    [0xFF] = "Reserved"
}

local fields = {}

-- SLL header
fields.sll_pkttype = ProtoField.uint16("sll.pkttype", "Packet type", base.HEX)
fields.sll_arphrd = ProtoField.uint16("sll.arphrd", "Link layer address type", base.HEX)
fields.sll_addrlen = ProtoField.uint16("sll.addrlen", "Address length", base.DEC)
fields.sll_addr = ProtoField.bytes("sll.addr", "Address")
fields.sll_protocol = ProtoField.uint16("sll.protocol", "Protocol", base.HEX)

-- Fixed-size bytes fields (for SPDM known sizes)
fields.spdm_nonce = ProtoField.bytes("spdm.nonce_fixed", "Nonce")
fields.spdm_slot_mask = ProtoField.bytes("spdm.slot_mask_fixed", "Slot Mask")
fields.spdm_ver_entry = ProtoField.bytes("spdm.ver_entry_fixed", "Version Entry")

-- MCTP fields
fields.mctp_version = ProtoField.uint8("mctp.version", "Header Version", base.DEC, hdr_ver, 0x0F)
fields.mctp_rsvd = ProtoField.uint8("mctp.rsvd", "Reserved", base.HEX, nil, 0xF0)
fields.mctp_dest = ProtoField.uint8("mctp.dest", "Destination EID", base.DEC)
fields.mctp_src = ProtoField.uint8("mctp.src", "Source EID", base.DEC)
fields.mctp_som = ProtoField.uint8("mctp.som", "Start of Message", base.DEC, yesno, 0x80)
fields.mctp_eom = ProtoField.uint8("mctp.eom", "End of Message", base.DEC, yesno, 0x60)
fields.mctp_pkt_seq = ProtoField.uint8("mctp.pkt_seq", "Packet Sequence", base.DEC, nil, 0x18)
fields.mctp_tag = ProtoField.uint8("mctp.tag", "Message Tag", base.DEC, nil, 0x07)
fields.mctp_hdr_digest = ProtoField.uint8("mctp.hdr_digest", "Header Digest", base.HEX)
fields.mctp_msg_type = ProtoField.uint8("mctp.msg_type", "Message Type", base.HEX, msg_types, 0x7F)
fields.mctp_integrity = ProtoField.uint8("mctp.integrity", "Integrity Check", base.DEC, yesno, 0x80)
fields.mctp_payload = ProtoField.bytes("mctp.payload", "MCTP Payload")

-- I2C SMBus fields (MCTP SMBus transport binding)
fields.i2c_reserved = ProtoField.uint8("i2c.reserved", "Reserved", base.HEX)
fields.i2c_command = ProtoField.uint8("i2c.command", "Command Code", base.HEX)
fields.i2c_byte_count = ProtoField.uint8("i2c.byte_count", "Byte Count", base.DEC)
fields.i2c_source_addr = ProtoField.uint8("i2c.source_addr", "Source Address", base.HEX)
fields.i2c_dest_addr = ProtoField.uint8("i2c.dest_addr", "Destination Address", base.HEX)

proto_mctp_i2c.fields = fields

-- ==========================================================================
-- SPDM fields
-- ==========================================================================

local reqres_types = {
    [0x81] = "Request: GET_DIGESTS",
    [0x82] = "Request: GET_CERTIFICATE",
    [0x83] = "Request: CHALLENGE",
    [0x84] = "Request: GET_VERSION",
    [0xE0] = "Request: GET_MEASUREMENTS",
    [0xE1] = "Request: GET_CAPABILITIES",
    [0xE3] = "Request: NEGOTIATE_ALGORITHMS",
    [0xFE] = "Request: VENDOR_DEFINED_REQUEST",
    [0xFF] = "Request: RESPOND_IF_READY",
    [0xE4] = "Request: KEY_EXCHANGE",
    [0xE5] = "Request: FINISH",
    -- Responses --
    [0x01] = "Response: DIGESTS",
    [0x02] = "Response: CERTIFICATE",
    [0x03] = "Response: CHALLENGE_AUTH",
    [0x04] = "Response: VERSION",
    [0x60] = "Response: MEASUREMENTS",
    [0x61] = "Response: CAPABILITIES",
    [0x63] = "Response: ALGORITHMS",
    [0x7E] = "Response: VENDOR_DEFINED_RESPONSE",
    [0x64] = "Response: KEY_EXCHANGE_RSP",
    [0x65] = "Response: FINISH_RSP",
    [0x7F] = "Response: ERROR"
}

-- SPDM protocols use [7:4]=Major, [3:0]=Minor
-- request/response is distinguished by bit 7 of the code

local spdm_fields = {}

spdm_fields.major = ProtoField.uint8("spdm.major", "Major Version", base.HEX, nil, 0xF0)
spdm_fields.minor = ProtoField.uint8("spdm.minor", "Minor Version", base.HEX, nil, 0x0F)
spdm_fields.reqres = ProtoField.uint8("spdm.reqres", "Request Response Code", base.HEX, reqres_types)
spdm_fields.param1 = ProtoField.uint8("spdm.param1", "Parameter 1", base.HEX)
spdm_fields.param2 = ProtoField.uint8("spdm.param2", "Parameter 2", base.HEX)
spdm_fields.ver_num_count = ProtoField.uint8("spdm.ver_num_count", "Version Number Count", base.DEC)
spdm_fields.ver_entry = ProtoField.bytes("spdm.ver_entry", "Version Entry")
spdm_fields.payload = ProtoField.bytes("spdm.payload", "Payload")
spdm_fields.reserved = ProtoField.bytes("spdm.reserved", "Reserved")

-- SPDM error fields
spdm_fields.error_code = ProtoField.uint8("spdm.error_code", "Error Code", base.HEX)
spdm_fields.error_data = ProtoField.uint8("spdm.error_data", "Error Data", base.HEX)

-- Capabilities flags
local MSCAP = {
    [0] = "Not Supported",
    [1] = "Supports, but can't generate signatures",
    [2] = "Supports totally",
    [3] = "Reserved"
}

local PSKCAP = {
    [0] = "Not Supported",
    [1] = "Supports pre-shared key",
    [2] = "Reserved",
    [3] = "Reserved"
}

spdm_fields.ct_exp = ProtoField.uint8("spdm.ct_exp", "CT Exponent", base.DEC)
spdm_fields.encrypt_cap = ProtoField.uint16("spdm.encrypt_cap", "Supports Encryption", base.HEX, yesno, 0x0040)
spdm_fields.mac_cap = ProtoField.uint16("spdm.mac_cap", "Supports Message Authentication", base.HEX, yesno, 0x0080)
spdm_fields.mut_auth_cap = ProtoField.uint16("spdm.mut_auth_cap", "Supports Mutual Authentication", base.HEX, yesno, 0x0001)
spdm_fields.key_ex_cap = ProtoField.uint16("spdm.key_ex_cap", "Supports Key Exchange", base.HEX, yesno, 0x0002)
spdm_fields.psk_cap = ProtoField.uint16("spdm.psk_cap", "Supports Pre-Shared Key", base.HEX, PSKCAP, 0x000C)
spdm_fields.encap_cap = ProtoField.uint16("spdm.encap_cap", "Supports Encapsulation", base.HEX, yesno, 0x0010)
spdm_fields.cert_cap = ProtoField.uint16("spdm.cert_cap", "Supports GET_DIGESTS and GET_CERTIFICATE", base.HEX, yesno, 0x0002)
spdm_fields.chal_cap = ProtoField.uint16("spdm.chal_cap", "Supports CHALLANGE message", base.HEX, yesno, 0x0004)
spdm_fields.meas_cap = ProtoField.uint16("spdm.meas_cap", "Measurement Capabilities", base.HEX, MSCAP, 0x0018)

-- Algorithm types
local BSymAlgo = {
    [0x001] = "TPM_ALG_RSASSA_2048",
    [0x002] = "TPM_ALG_RSAPSS_2048",
    [0x004] = "TPM_ALG_RSASSA_3072",
    [0x008] = "TPM_ALG_RSAPSS_3072",
    [0x010] = "TPM_ALG_ECDSA_ECC_NIST_P256",
    [0x020] = "TPM_ALG_RSASSA_4096",
    [0x040] = "TPM_ALG_RSAPSS_4096",
    [0x080] = "TPM_ALG_ECDSA_ECC_NIST_P384",
    [0x100] = "TPM_ALG_ECDSA_ECC_NIST_P521"
}

local BHshAlgo = {
    [0x01] = "TPM_ALG_SHA_256",
    [0x02] = "TPM_ALG_SHA_384",
    [0x04] = "TPM_ALG_SHA_512",
    [0x08] = "TPM_ALG_SHA3_256",
    [0x10] = "TPM_ALG_SHA3_384",
    [0x20] = "TPM_ALG_SHA3_512"
}

local AlgTypes = {
    [2] = "DHE",
    [3] = "AEADCipherSuite",
    [4] = "ReqBaseAsymAlg",
    [5] = "KeySchedule"
}

spdm_fields.base_asym_sel = ProtoField.uint32("spdm.base_asym_sel", "Base Asymmetric Algorithm", base.HEX, BSymAlgo)
spdm_fields.base_hsh_sel = ProtoField.uint32("spdm.base_hsh_sel", "Base Hash Algorithm", base.HEX, BHshAlgo)
spdm_fields.ext_asy_c = ProtoField.uint8("spdm.ext_asy_c", "Extended Asym Count", base.DEC)
spdm_fields.ext_hsh_c = ProtoField.uint8("spdm.ext_hsh_c", "Extended Hash Count", base.DEC)
spdm_fields.alg_type = ProtoField.uint8("spdm.alg_type", "Algorithm Type", base.HEX, AlgTypes)
spdm_fields.fixed_alg_count = ProtoField.uint8("spdm.fixed_alg_count", "Fixed Algorithm Count", base.DEC, nil, 0xF0)
spdm_fields.ext_alg_count = ProtoField.uint8("spdm.ext_alg_count", "Extended Algorithm Count", base.DEC, nil, 0x0F)
spdm_fields.alg_supported = ProtoField.bytes("spdm.alg_supported", "Supported Algorithms")
spdm_fields.meas_spec = ProtoField.uint8("spdm.meas_spec", "Measurement Specification", base.HEX)

-- DIGESTS response fields
spdm_fields.slot_mask = ProtoField.bytes("spdm.slot_mask", "Slot Mask")
spdm_fields.digest_data = ProtoField.bytes("spdm.digest_data", "Digest(s)")

-- CERTIFICATE
spdm_fields.cert_offset = ProtoField.uint16("spdm.cert_offset", "Offset", base.DEC)
spdm_fields.cert_length = ProtoField.uint16("spdm.cert_length", "Length", base.DEC)

-- CHALLENGE
spdm_fields.nonce = ProtoField.bytes("spdm.nonce", "Nonce")
spdm_fields.which_cert = ProtoField.uint8("spdm.which_cert", "Certificate Slot", base.DEC)

-- MEASUREMENTS
spdm_fields.num_blocks = ProtoField.uint8("spdm.num_blocks", "Number of Measurement Blocks", base.DEC)
spdm_fields.meas_oper = ProtoField.uint8("spdm.meas_oper", "Measurement Operation", base.HEX)
spdm_fields.summ_hash_type = ProtoField.uint8("spdm.summ_hash_type", "Summary Hash Type", base.HEX)

-- Length field (32-bit)
spdm_fields.length32 = ProtoField.uint32("spdm.length", "Length", base.DEC)

proto_spdm.fields = spdm_fields

-- ==========================================================================
-- SPDM dissector helper
-- ==========================================================================

function dissect_spdm(buffer, tree, offset, payload_len)
    if payload_len < 4 then return offset end
    
    local spdm_tree = tree:add(proto_spdm, buffer(offset, payload_len),
                               "Security Protocol Data Model (SPDM)")
    
    -- SPDM header: Version(1) + Code(1) + Param1(1) + Param2(1)
    local ver_byte = buffer(offset, 1):uint()
    local major = bit.rshift(bit.band(ver_byte, 0xF0), 4)
    local minor = bit.band(ver_byte, 0x0F)
    local code = buffer(offset + 1, 1):uint()
    local p1 = buffer(offset + 2, 1):uint()
    local p2 = buffer(offset + 3, 1):uint()
    
    spdm_tree:add(spdm_fields.major, buffer(offset, 1))
    spdm_tree:add(spdm_fields.minor, buffer(offset, 1))
    spdm_tree:add(spdm_fields.reqres, buffer(offset + 1, 1))
    spdm_tree:add(spdm_fields.param1, buffer(offset + 2, 1))
    spdm_tree:add(spdm_fields.param2, buffer(offset + 3, 1))
    
    local info_str = ("SPDM v%d.%d"):format(major, minor)
    local name = reqres_types[code]
    if name then
        info_str = info_str .. " " .. name
    else
        info_str = info_str .. string.format(" Code=0x%02x", code)
    end
    
    -- Set protocol column
    if proto_spdm.description then
        -- already set
    end
    
    local begin = offset + 4
    
    -- Error response (0x7F)
    if code == 0x7F then
        if payload_len >= begin - offset + 2 then
            spdm_tree:add(spdm_fields.error_code, buffer(begin, 1))
            spdm_tree:add(spdm_fields.error_data, buffer(begin + 1, 1))
            info_str = info_str .. (" [Error 0x%02x%02x]"):format(p1, p2)
        end
        return begin + 2
    end
    
    -- GET_VERSION response (0x04)
    if code == 0x04 then
        if payload_len >= begin - offset + 2 then
            local num_ver = buffer(begin, 2):le_uint()
            spdm_tree:add(spdm_fields.ver_num_count, buffer(begin, 2))
            for i = 0, num_ver - 1 do
                local ve = begin + 2 + i * 2
                if ve + 2 <= offset + payload_len then
                    local vmajor = bit.rshift(bit.band(buffer(ve, 1):uint(), 0xF0), 4)
                    local vminor = bit.band(buffer(ve, 1):uint(), 0x0F)
                    local uvnum = bit.rshift(bit.band(buffer(ve + 1, 1):uint(), 0xF0), 4)
                    local alpha = bit.band(buffer(ve + 1, 1):uint(), 0x0F)
                    spdm_tree:add(spdm_fields.ver_entry, buffer(ve, 2))
                           :set_text(("Version %d: v%d.%d.%d Alpha=%d"):format(i, vmajor, vminor, uvnum, alpha))
                end
            end
        end
    end
    
    -- CAPABILITIES response (0x61)
    if code == 0x61 then
        if payload_len >= begin + 6 - offset then
            local ct = buffer(begin, 1):uint()
            spdm_tree:add(spdm_fields.ct_exp, buffer(begin, 1))
            -- Flags at begin+1 to begin+3 (3 bytes? Actually 4 bytes in 1.1)
            local flags = buffer(begin + 2, 4):le_uint()
            local flags_tree = spdm_tree:add(buffer(begin + 2, 4), "Capabilities Flags: 0x%08x", flags)
            -- Only show relevant bits
            if bit.band(flags, 0x0001) ~= 0 then flags_tree:add(spdm_fields.mut_auth_cap, buffer(begin + 2, 2)) end
            if bit.band(flags, 0x0002) ~= 0 then flags_tree:add(spdm_fields.key_ex_cap, buffer(begin + 2, 2)) end
            if bit.band(flags, 0x000C) ~= 0 then flags_tree:add(spdm_fields.psk_cap, buffer(begin + 2, 2)) end
            if bit.band(flags, 0x0010) ~= 0 then flags_tree:add(spdm_fields.encap_cap, buffer(begin + 2, 2)) end
            if bit.band(flags, 0x0002) ~= 0 then flags_tree:add(spdm_fields.cert_cap, buffer(begin + 3, 1)) end
            if bit.band(flags, 0x0004) ~= 0 then flags_tree:add(spdm_fields.chal_cap, buffer(begin + 3, 1)) end
            if bit.band(flags, 0x0018) ~= 0 then flags_tree:add(spdm_fields.meas_cap, buffer(begin + 3, 1)) end
        end
    end
    
    -- ALGORITHMS response (0x63)
    if code == 0x63 then
        if payload_len >= begin + 8 - offset then
            local alg_len = buffer(begin, 2):le_uint()
            spdm_tree:add(spdm_fields.length32, buffer(begin, 2))
            local meas_spec = buffer(begin + 2, 1):uint()
            spdm_tree:add(spdm_fields.meas_spec, buffer(begin + 2, 1))
            
            -- BaseAsymSel at begin+4 (4 bytes)
            local basym = buffer(begin + 4, 4):le_uint()
            local asym_tree = spdm_tree:add(spdm_fields.base_asym_sel, buffer(begin + 4, 4))
            for mask, name in pairs(BSymAlgo) do
                if bit.band(basym, mask) ~= 0 then
                    asym_tree:add(buffer(begin + 4, 4), ("  %s"):format(name))
                end
            end
            
            -- BaseHashSel at begin+8 (4 bytes)
            local bhsh = buffer(begin + 8, 4):le_uint()
            local hsh_tree = spdm_tree:add(spdm_fields.base_hsh_sel, buffer(begin + 8, 4))
            for mask, name in pairs(BHshAlgo) do
                if bit.band(bhsh, mask) ~= 0 then
                    hsh_tree:add(buffer(begin + 8, 4), ("  %s"):format(name))
                end
            end
        end
    end
    
    -- DIGESTS response (0x01)
    if code == 0x01 then
        local slot_count = bit.band(p1, 0x0F)
        if slot_count == 0 then slot_count = bit.band(p2, 0x0F) end
        if slot_count == 0 then slot_count = 1 end
        spdm_tree:add(spdm_fields.slot_mask, buffer(begin, 8))
        spdm_tree:add(spdm_fields.digest_data, buffer(begin + 8, payload_len - (begin - offset) - 8))
        info_str = info_str .. (" (%d slots)"):format(slot_count)
    end
    
    -- MEASUREMENTS response (0x60)
    if code == 0x60 then
        local nb = buffer(offset + 2, 1):uint()
        spdm_tree:add(spdm_fields.num_blocks, buffer(offset + 2, 1))
        info_str = info_str .. (" (%d blocks)"):format(nb)
    end
    
    -- ERROR response
    if code == 0x7F then
        local err_code = p1
        local err_data = p2
        info_str = info_str .. (" [Error 0x%02x %02x]"):format(err_code, err_data)
    end
    
    -- GET_MEASUREMENTS request (0xE0)
    if code == 0xE0 then
        if p2 == 0xFF then
            info_str = info_str .. " (all measurements)"
        elseif p2 ~= 0 then
            info_str = info_str .. (" (block %d)"):format(p2)
        end
    end
    
    -- GET_CAPABILITIES request (0xE1)
    if code == 0xE1 then
        if payload_len >= 4 then
            -- CTExponent at begin, flags at begin+1
            if payload_len >= 8 then
                local flags = buffer(begin + 1, 4):le_uint()
                info_str = info_str .. (" [Flags=0x%04x]"):format(flags)
            end
        end
    end
    
    -- Set protocol column info
    info = info_str
    
    return offset + payload_len
end

-- ==========================================================================
-- Main dissector
-- ==========================================================================

-- Debug counter
local mctp_i2c_debug_count = 0

function proto_mctp_i2c.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length == 0 then return end
    
    pinfo.cols.protocol = "MCTP-I2C"
    
    -- Add SLL header then MCTP data
    local sll_subtree = tree:add(proto_mctp_i2c, buffer(0, 16),
                                 "Linux SLL (cooked capture)")
    sll_subtree:add(fields.sll_pkttype, buffer(0, 2))
    sll_subtree:add(fields.sll_arphrd, buffer(2, 2))
    sll_subtree:add(fields.sll_addrlen, buffer(4, 2))
    
    local data_offset = 16
    
    -- Add MCTP protocol tree item for remaining data
    local subtree = tree:add(proto_mctp_i2c, buffer(16, length - 16),
                             "MCTP over I2C (SMBus)")
    
    -- Parse the SLL header to determine packet direction
    -- SLL pkttype: 4=outgoing(request), 0=incoming(response)
    local sll_pkttype = buffer(0, 2):uint()  -- big-endian
    local is_request = (sll_pkttype == 4)
    
    -- Skip SLL header (16 bytes)
    -- The MCTP packet structure after SLL varies by capture tool.
    -- BRCM tool wrapper: 8-byte header + 2-byte seq/dir + MCTP data
    -- We search for SPDM data patterns in the payload.
    
    local data_offset = 16  -- skip SLL header
    
    
    -- MCTP transport header parsing
    -- Standard MCTP header (5 bytes for transport):
    --   Byte 0: [3:0]=HdrVer, [7:4]=Reserved
    --   Byte 1: Destination EID
    --   Byte 2: Source EID
    --   Byte 3: [7]=SOM, [6]=EOM, [5:4]=PktSeq, [3:0]=MessageTag
    --   Byte 4: [7]=IntegrityCheck, [6:0]=MessageType     ← MsgType at bits 6:0
    --     MessageType 0x05 = SPDM
    -- After MCTP header, SPDM data starts immediately.
    -- SPDM format: [Version(1)][Code(1)][Param1(1)][Param2(1)][Payload...]
    
    -- Scan all packets for MCTP transport header with MsgType=0x05 (SPDM)
    local spdm_start = nil
    local spdm_len = 0
    local mctp_found = false
    
    -- Search for MCTP header pattern: valid header + MsgType 0x05
    -- Need at least 5 bytes (MCTP transport header)
    for i = data_offset, length - 5 do
        -- Byte 4 of MCTP header = [7]=Integrity, [6:0]=MsgType
        -- Valid MCTP version byte 0: version <= 1
        local b0 = buffer(i, 1):uint()
        local hdr_ver = bit.band(b0, 0x0F)
        if hdr_ver <= 1 then
            -- Check byte 4 (i+4) for MsgType = 0x05 (SPDM)
            if i + 4 < length then
                local mctp_type = bit.band(buffer(i + 4, 1):uint(), 0x7F)
                if mctp_type == 0x05 then
                    -- Found MCTP header with SPDM type
                    local mctp_tree = subtree:add(proto_mctp_i2c, buffer(i, 5),
                                                  "MCTP Transport (SPDM)")
                    mctp_tree:add(fields.mctp_version, buffer(i, 1))
                    mctp_tree:add(fields.mctp_dest, buffer(i + 1, 1))
                    mctp_tree:add(fields.mctp_src, buffer(i + 2, 1))
                    mctp_tree:add(fields.mctp_som, buffer(i + 3, 1))
                    mctp_tree:add(fields.mctp_eom, buffer(i + 3, 1))
                    mctp_tree:add(fields.mctp_tag, buffer(i + 3, 1))
                    mctp_tree:add(fields.mctp_msg_type, buffer(i + 4, 1))
                    
                    local som = bit.rshift(buffer(i + 3, 1):uint(), 7)
                    local eom = bit.rshift(bit.band(buffer(i + 3, 1):uint(), 0x40), 6)
                    local tag = bit.band(buffer(i + 3, 1):uint(), 0x07)
                    pinfo.cols.info = ("MCTP SOM=%d EOM=%d Type=SPDM Tag=%d"):format(som, eom, tag)
                    
                    spdm_start = i + 5  -- SPDM starts after 5-byte MCTP header
                    spdm_len = length - spdm_start
                    mctp_found = true
                    break
                end
            end
        end
    end
    
    if spdm_start and spdm_len >= 4 then
        pinfo.cols.protocol = "SPDM"
        pinfo.cols.info = "SPDM"
        subtree:set_text("MCTP-I2C (SPDM data)")
        
        -- Add MCTP transport info if we can find it
        local mctp_tree = subtree:add(proto_mctp_i2c, buffer(0, spdm_start),
                                       "MCTP Transport")
        
        -- Look for MCTP header pattern (look for MessageType = 0x05 = SPDM)
        -- MCTP header is 6 bytes: Version(1) + Dest(1) + Src(1) + FlagsTag(1) + Integrity(1) + Type(1)
        for j = 0, spdm_start - 1 do
            if j + 6 <= spdm_start then
                local msg_type = buffer(j + 5, 1):uint()
                msg_type = bit.band(msg_type, 0x7F)
                if msg_type == 0x05 then
                    -- Found MCTP header
                    mctp_tree:add(fields.mctp_version, buffer(j, 1))
                    mctp_tree:add(fields.mctp_dest, buffer(j + 1, 1))
                    mctp_tree:add(fields.mctp_src, buffer(j + 2, 1))
                    mctp_tree:add(fields.mctp_som, buffer(j + 3, 1))
                    mctp_tree:add(fields.mctp_eom, buffer(j + 3, 1))
                    mctp_tree:add(fields.mctp_pkt_seq, buffer(j + 3, 1))
                    mctp_tree:add(fields.mctp_tag, buffer(j + 3, 1))
                    mctp_tree:add(fields.mctp_integrity, buffer(j + 4, 1))
                    mctp_tree:add(fields.mctp_msg_type, buffer(j + 5, 1))
                    
                    local som = bit.band(buffer(j + 3, 1):uint(), 0x80)
                    local eom = bit.band(buffer(j + 3, 1):uint(), 0x40)
                    local tag = bit.band(buffer(j + 3, 1):uint(), 0x07)
                    pinfo.cols.info = ("MCTP SOM=%d EOM=%d Type=SPDM Tag=%d"):format(
                        som ~= 0 and 1 or 0, eom ~= 0 and 1 or 0, tag)
                    break
                end
            end
        end
        
        -- Dissect SPDM
        dissect_spdm(buffer, subtree, spdm_start, spdm_len)
    else
        -- Raw MCTP data without SPDM
        subtree:add(fields.mctp_payload, buffer(0, length))
        pinfo.cols.info = "MCTP Packet"
    end
end

-- ==========================================================================
-- Register as post-dissector to inspect all SLL frames
-- Post-dissector runs after built-in SLL parser, gets the full buffer
-- ==========================================================================

-- Use post-dissector to add MCTP/SPDM info after built-in SLL parsing
register_postdissector(proto_mctp_i2c)

-- Also register for DLT_USER0 via decode-as
local wtap_tbl = DissectorTable.get("wtap_encap")
if wtap_tbl then
    wtap_tbl:add_for_decode_as(proto_mctp_i2c)
end

-- ==========================================================================
-- Register SPDM as a dissector for direct use
-- ==========================================================================

function proto_spdm.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length < 4 then return 0 end
    
    local b0 = buffer(0, 1):uint()
    local b1 = buffer(1, 1):uint()
    
    local major = bit.rshift(bit.band(b0, 0xF0), 4)
    local minor = bit.band(b0, 0x0F)
    
    if major == 1 and minor <= 2 and reqres_types[b1] ~= nil then
        pinfo.cols.protocol = "SPDM"
        dissect_spdm(buffer, tree, 0, length)
        return length
    end
    return 0
end

local raw_table = DissectorTable.get("wtap_encap")
if raw_table then
    raw_table:add_for_decode_as(proto_spdm)
end

print("SPDM-I2C dissector loaded (post-dissector)")
