--[[
  --------------------------------------------------------------------
  Wireshark dissector written in Lua for the Mikrotik Winbox Protocol.

  Please note that this dissector only works when 'Secure Mode'
  is disabled within the client.
  --------------------------------------------------------------------
]]


-- Header field offsets (in bytes)
local OFFSET_CHUNKFIELD = 0
local OFFSET_TYPEFIELD = 1
local OFFSET_LENGTHFIELD = 2
local OFFSET_MAGICFIELD = 4

-- Header field sizes (in bytes)
local LEN_CHUNKFIELD = 1
local LEN_TYPEFIELD = 1
local LEN_LENGTHFIELD = 2
local LEN_MAGICFIELD = 2
local LEN_HEADER = LEN_CHUNKFIELD + LEN_TYPEFIELD +
  LEN_LENGTHFIELD + LEN_MAGICFIELD

-- Other known sizes/offsets (in bytes)
local LEN_TYPEID = 4
local LEN_CHUNKDATA = 2
local OFFSET_DATASTART = OFFSET_MAGICFIELD + LEN_MAGICFIELD

-- Wireshark protocol fields
local Winbox_Protocol_TCP = Proto("Winbox","Winbox Protocol")
local ft =  Winbox_Protocol_TCP.fields

ft.chunkOffset = ProtoField.uint8("Chunk.Offset", "Chunk Offset", base.HEX)
ft.wbType = ProtoField.uint8("Message.Type", "Type", base.HEX)
ft.wbMessageLength = ProtoField.uint16("Message.Length", "Message Length",
                                       base.HEX)
ft.wbMagicBytes = ProtoField.string("Magic", "Magic")

-- Winbox Data Type Table for Display
ft.wbMessage = ProtoField.bytes("Winbox.Message", "Message")
ft.wbMessageHeader = ProtoField.bytes("Winbox.Message.Header", "Message Header")

ft.wbElement = ProtoField.bytes("Winbox.Element", "Element")
ft.wbType = ProtoField.uint32("Winbox.Type", "Type ID", base.HEX)

ft.wbBoolValue = ProtoField.bool("Winbox.Boolean.Value", "Value")
ft.wbU32RefValue = ProtoField.uint8("Winbox.U32Ref.Value", "Value", base.HEX)
ft.wbU32RefValue32 = ProtoField.uint32("Winbox.U32Ref.Value", "Value", base.HEX)
ft.wbU64RefValue = ProtoField.uint64("Winbox.U64Ref.Value", "Value", base.HEX)
ft.wbAddr6RefValue = ProtoField.uint16("Winbox.Addr6Ref.Value", "Value",
                                       base.HEX)
ft.wbStringRefValue = ProtoField.string("Winbox.StringRef.Content", "Content")
ft.wbU32ArrayElements = ProtoField.uint32("Winbox.U32ArrayRef.Size",
                                          "Size", base.HEX)
ft.wbU64ArrayRefValue = ProtoField.bytes("Winbox.U64ArrayRef.Content",
                                         "Content")
ft.wbRawRefValue = ProtoField.uint8("Winbox.RawRef.uint8", "uint8")
ft.wbRawRefElements = ProtoField.uint32("Winbox.RawRef.Size", "Size",
                                        base.HEX)
ft.wbMsgRefValue = ProtoField.bytes("Winbox.MsgRef.Content", "Content")
ft.wbMsgRefElements = ProtoField.uint32("Winbox.MsgRef.Size", "Size",
                                        base.HEX)
ft.wbMsgArrayRefElements = ProtoField.uint32("Winbox.MsgArrayRef.Size",
                                             "Size", base.HEX)


--------------------------------------------------------------------------------
--                      ╭──────────────────────────╮
--                        Helper/Utility Functions
--                      ╰──────────────────────────╯
--------------------------------------------------------------------------------
-- ╔═════════════╗
--   Debug Print
-- ╚═════════════╝
function printf(category, str)
  print(string.format("[%s] %s", category, str))
end

-- ╔══════════════════╗
--   Hex Dump for TVB
-- ╚══════════════════╝
-- Accepts integer offset and TVB
function hexDump(offset,buf)
  local bufLength = buf():len()
  local bytesUsed = 0
  local columnLength = 16
  print(string.format("[hexDump] bytesUsed: 0x%x, bufLength: 0x%x, \
    columnLength: 0x%x", bytesUsed, bufLength, columnLength))

  -- Loop until all bytes consumed
  local i = 0
  while bytesUsed < bufLength do
    -- If less than 16 bytes remain, use a smaller columnLength
    if (bufLength-bytesUsed) < columnLength then
      columnLength = bufLength - bytesUsed
    end

    -- Grab 1->columnLength bytes at a time
    local currentChunk = buf(i, columnLength):bytes()
    -- Convert array to hex string and insert a space between each hex byte
    local hexString = tostring(currentChunk):gsub('..'," %1")
    -- Replace non-ascii bytes with a '.'
    local asciiString = buf(i,columnLength):string()
      :gsub("[\x00-\x20][\x7e-\xff]*", ".")

    -- Display offset
    io.write(string.format('%08X ',i+offset))
    -- Display hex representation
    io.write(hexString)
    -- Pad with spaces after hex data
    io.write(string.rep(' ',3*(16-columnLength)+2))
    -- Display ASCII representation
    io.write(asciiString, "\n")
    bytesUsed = bytesUsed + columnLength
    i = i + 16
  end
end

-- ╔════════════════╗
--   Unsign Integer
-- ╚════════════════╝
-- The bit library always returns a Signed Int
-- This function will convert a 32-bit Int to Unsigned
local function unsign(n)
  if n < 0 then
    n = 4294967296 + n
  end
  return n
end

-- ╔══════════════════════╗
--   Bitwise Math Helpers
-- ╚══════════════════════╝
local band = bit.band
local rShift = bit.rshift

--------------------------------------------------------------------------------
--                        ╭───────────────────────╮
--                          Code String Resolvers
--                        ╰───────────────────────╯
--
-- Helper functions to retrieve code strings for any applicable type ID or
-- value
--------------------------------------------------------------------------------
-- ╔═══════════════════════════════╗
--   Code String Resolution Tables
-- ╚═══════════════════════════════╝
commandCode = {
  CMD_NOOP          = 0xFE0000,
  CMD_GETPOLICIES   = 0xFE0001,
  CMD_GETOBJ        = 0xFE0002,
  CMD_SETOBJ        = 0xFE0003,
  CMD_GETALL        = 0xFE0004,
  CMD_ADDOBJ        = 0xFE0005,
  CMD_REMOVEOBJ     = 0xFE0006,
  CMD_MOVEOBJ       = 0xFE0007,
  CMD_SETFORM       = 0xFE0008,
  CMD_NOTIFY        = 0xFE000B,
  CMD_GET           = 0xFE000D,
  CMD_SET           = 0xFE000E,
  CMD_START         = 0xFE000F,
  CMD_POLL          = 0xFE0010,
  CMD_CANCEL        = 0xFE0011,
  CMD_SUBSCRIBE     = 0xFE0012,
  CMD_UNSUBSCRIBE   = 0xFE0013,
  CMD_DISCONNECTED  = 0xFE0014,
  CMD_GETCOUNT      = 0xFE0015,
  CMD_RESET         = 0xFE0016
}

typeCode = {
  TYPE_REQUEST        = 0x1,
  TYPE_REPLY          = 0x2
}

statusCode = {
  STATUS_OK           = 0x1,
  STATUS_ERROR        = 0x2
}

errorCode = {
  ERROR_UNKNOWN       = 0xFE0001,
  ERROR_BRKPATH       = 0xFE0002,
  ERROR_NOTIMP        = 0xFE0003,
  ERROR_UNKNOWNID     = 0xFE0004,
  ERROR_MISSING       = 0xFE0005,
  ERROR_FAILED        = 0xFE0006,
  ERROR_EXISTS        = 0xFE0007,
  ERROR_NOTALLOWED    = 0xFE0009,
  ERROR_TOOBIG        = 0xFE000A,
  ERROR_UNKNOWNNEXTID = 0xFE000B,
  ERROR_BUSY          = 0xFE000C,
  ERROR_TIMEOUT       = 0xFE000D,
  ERROR_TOOMUCH       = 0xFE000E
}

typeIDCode = {
  SYS_TO              = 0xFF0001,
  SYS_FROM            = 0xFF0002,
  SYS_TYPE            = 0xFF0003,
  SYS_STATUS          = 0xFF0004,
  SYS_REPLYEXP        = 0xFF0005,
  SYS_REQID           = 0xFF0006,
  SYS_CMD             = 0xFF0007,
  SYS_ERRNO           = 0xFF0008,
  SYS_ERRSTR          = 0xFF0009,
  SYS_USER            = 0xFF000A,
  SYS_POLICY          = 0xFF000B,
  SYS_CTRL            = 0xFF000D,
  SYS_CTRL_ARG        = 0xFF000F,
  SYS_USER_ID         = 0xFF0010,
  SYS_NOTIFYCMD       = 0xFF0011,
  SYS_ORIGINATOR      = 0xFF0012,
  SYS_RADDR6          = 0xFF0013,
  SYS_DREASON         = 0xFF0016,
  STD_ID              = 0xFE0001,
  STD_OBJS            = 0xFE0002,
  STD_GETALLID        = 0xFE0003,
  STD_GETALLNO        = 0xFE0004,
  STD_NEXTID          = 0xFE0005,
  STD_UNDOID          = 0xFE0006,
  STD_DYNAMIC         = 0xFE0007,
  STD_INACTIVE        = 0xFE0008,
  STD_DESCR           = 0xFE0009,
  STD_DISABLED        = 0xFE000A,
  STD_FINISHED        = 0xFE000B,
  STD_FILTER          = 0xFE000C,
  STD_PRESET          = 0xFE000D,
  STD_PAGENO          = 0xFE000E,
  STD_PAGE            = 0xFE000F,
  STD_NAME            = 0xFE0010,
  STD_INTERVAL        = 0xFE0011,
  STD_VERSION         = 0xFE0012,

  STD_DEAD            = 0xFE0013,
  STD_COUNT           = 0xFE0014,
  STD_GETALL_COOKIE   = 0xFE0015,
  STD_QUERY           = 0xFE0016,
  STD_QUERY_OP        = 0xFE0017,
  STD_MAXOBJS         = 0xFE0018,
  STD_OBJ_COUNT       = 0xFE0019,
  STD_CLASS           = 0xFE001A,
  STD_SNMP_QUERY      = 0xFE001B,

  -- If no matches, compare with 'value & 0xFF0000'
  PPPMAN              = 0X0b0000,
  CONSOLE             = 0X110000,
  LOCAL               = 0Xfd0000,
  STD                 = 0Xfe0000,
  SYS                 = 0Xff0000,
  CERM                = 0X120000,
  ROUTE               = 0X2c0000,
  BRIDGE              = 0X0e0000,
  DISKD               = 0X0f0000,
  DUDE                = 0X100000,
  RADIUS              = 0X0c0000,
  HOTPLUG             = 0X0d0000,
  RADV                = 0X050000,
  UNDO                = 0X080000,
  LOG                 = 0X090000,
  MEPTY               = 0X0a0000,
  SYSTEM              = 0X060000,
  PING                = 0X070000,
  MODULER             = 0X020000,
  SERMGR              = 0X030000,
  NOTIFY              = 0X040000,
  NET                 = 0X010000
}

-- ╔════════════════════════════╗
--   Flip Key/Value Table Pairs
-- ╚════════════════════════════╝
-- Invert Key/Value pairs during execution to keep the table more easily
-- readable
function flipKeyValues(t)
  local s={}
  for k,v in pairs(t) do
    s[v]=k
  end
  return s
end

-- ╔═══════════════════╗
--   Type ID -> String
-- ╚═══════════════════╝
function getTypeIDString(typeRaw)
  local codeString = nil
  local key = band(typeRaw:le_uint(),0xffffff)
  -- If the first key fails a lookup, try this one
  local key2 = band(typeRaw:le_uint(),0xff0000)
  local invertedTable = flipKeyValues(typeIDCode)
  if invertedTable[key] ~= nil then
    codeString = invertedTable[key]
  elseif invertedTable[key2] ~= nil  then
    codeString = invertedTable[key2]
  else
    -- Always returns a string, even a hex-formatted one
    return string.format("::0x%x", typeRaw:le_uint())
  end
  return string.format("::%s", codeString)
end

-- ╔═════════════════╗
--   Value -> String
-- ╚═════════════════╝
local typeCodeTable = flipKeyValues(typeCode)
local statusCodeTable = flipKeyValues(statusCode)
local commandCodeTable = flipKeyValues(commandCode)
local errorCodeTable = flipKeyValues(errorCode)

function getValueString(typeRaw, valueRaw)
  local typeMask = band(typeRaw:le_uint(),0xffffff)
  local valueMask = band(valueRaw:le_uint(),0xffffff)
  local lookupTable
  local codeString = nil


  -- SYS_TYPE
  if typeMask == 0xFF0003 and typeCodeTable[valueMask] ~= nil then
    codeString = typeCodeTable[valueMask]
  -- SYS_STATUS
  elseif typeMask == 0xFF0004 and statusCodeTable[valueMask] ~= nil then
    codeString = statusCodeTable[valueMask]
  -- SYS_CMD
  elseif typeMask == 0xff0007 and commandCodeTable[valueMask] ~= nil then
    codeString = commandCodeTable[valueMask]
  -- SYS_ERRNO
  elseif typeMask == 0xff0008 and errorCodeTable[valueMask] ~= nil then
    codeString = errorCodeTable[valueMask]
  -- Return a hex string representing the raw value if no code found
  else
    return string.format("0x%x", valueRaw:le_uint())
  end

  return string.format("%s", codeString)
end

--------------------------------------------------------------------------------
--                           ╭─────────────────╮
--                             Type ID Parsers
--                           ╰─────────────────╯
--
-- These functions parse and display data for their applicable
-- type IDs. Each function returns the number of bytes consumed
-- through parsing.
--------------------------------------------------------------------------------
-- ╔════════════════════╗
--   Utility: Get Index
-- ╚════════════════════╝
-- Return a hexidecimal String representing the index number of the typeID
function getIndex(typeRaw)
  local index = band(typeRaw:le_uint(),0xff)
  return string.format("%x", index)
end

-- ╔══════════════════════════╗
--   Utility: Get Vector Size
-- ╚══════════════════════════╝
-- Calculate and return the size of a vector and the corresponding data offset
getVectorSize = function(typeRaw, buffer)
  local vectorSize = 0
  local dataOffset = 0
  local isSingleByte = band(typeRaw:le_uint(),0x1000000)

  if isSingleByte == 0 then  -- Use 2 Bytes instead of 1
    vectorSize = buffer(4,2)
    dataOffset = 6
  else
    vectorSize = buffer(4,1)
    dataOffset = 5
  end

  return vectorSize, dataOffset
end

-- ╔════════════════════════╗
--   Forward-Define Parsers
-- ╚════════════════════════╝
-- This avoids functions not being declared before
-- a recursive function is called
local boolContent
local u32RefContent
local u64RefContent
local addr6RefContent
local stringRefContent
local u32ArrayRefContent
local u64ArrayRefContent
local rawRefContent
local msgRefContent
local contentFunctions
local removeChunkOffsetBytes
local parseNestedWinboxMessage
local msgArrayRefContent
local parseRootWinboxMessage

-- ╔═══════════════════════════╗
--   Element: Boolean Reference
-- ╚═══════════════════════════╝
boolContent = function(typeRaw, typeHash, buffer, tree)
  local typeIndex = getIndex(typeRaw)
  local rawValue = band(rShift(typeRaw:le_uint(),0x18),0x1)
  local value = string.format("%s", rawValue and 'True' or 'False')

  local bytesUsed = 4

  local typeString = string.format("bool.%s%s = %s", typeIndex, getTypeIDString(typeRaw),
                                   value)

  local typeSubTree = tree:add(ft.wbElement,buffer(0,bytesUsed))
    :set_text(typeString)

  typeSubTree:add_le(ft.wbType, typeRaw)
  typeSubTree:add_le(ft.wbBoolValue, rawValue)
  return bytesUsed
end

-- ╔═══════════════════════════╗
--   Element: UINT32 Reference
-- ╚═══════════════════════════╝
u32RefContent = function(typeRaw, typeHash, buffer, tree)
  local typeIndex = getIndex(typeRaw)
  local typeString
  local typeSubTree
  local bytesUsed = 0
  local typeIDString = getTypeIDString(typeRaw)
  local valueString

  -- If this hash is NULL then use 4 bytes instead of 1
  local isDWORD = band(typeRaw:le_uint(),0x1000000)

  if isDWORD == 0 then  -- Use 4 Bytes instead of 1
    local value = buffer(4,4)
    bytesUsed = 8

    valueString = getValueString(typeRaw, value)
    typeString = string.format("u32.%s%s = %s", typeIndex, typeIDString, valueString)
    typeSubTree = tree:add(ft.wbElement,buffer(0,bytesUsed))
      :set_text(typeString)

    typeSubTree:add_le(ft.wbType, typeRaw)
    typeSubTree:add_le(ft.wbU32RefValue32, value)
  else
    local value = buffer(4,1)
    bytesUsed = 5

    valueString = getValueString(typeRaw, value)
    typeString = string.format("u32.%s%s = %s", typeIndex, typeIDString, valueString)
    typeSubTree = tree:add(ft.wbElement,buffer(0,bytesUsed))
      :set_text(typeString)

    typeSubTree:add_le(ft.wbType, typeRaw)
    typeSubTree:add_le(ft.wbU32RefValue, value)
  end

  return bytesUsed
end

-- ╔═══════════════════════════╗
--   Element: UINT64 Reference
-- ╚═══════════════════════════╝
u64RefContent = function(typeRaw, typeHash, buffer, tree)
  local typeIndex = getIndex(typeRaw)
  local typeIDString = getTypeIDString(typeRaw)
  local typeString
  local value = buffer(4,8)
  local bytesUsed = 12

  typeString = string.format("u64.%s%s= 0x%x", typeIndex, typeIDString,
                             value:le_uint64():tonumber())

  local typeSubTree = tree:add(ft.wbElement,buffer(0,bytesUsed))
    :set_text(typeString)

  typeSubTree:add_le(ft.wbType, typeRaw)
  typeSubTree:add_le(ft.wbU64RefValue, value)
  return bytesUsed
end

-- ╔═════════════════════════════════╗
--   Element: IPV6 Address Reference
-- ╚═════════════════════════════════╝
addr6RefContent = function(typeRaw, typeHash, buffer, tree)
  -- local values = buffer(4,16)
  local bytesUsed = 20
  local typeIndex = getIndex(typeRaw)

  local typeString = string.format("ipv6Addr.%s = ",typeIndex)
  local typeSubTree = tree:add(ft.wbElement,buffer(0,bytesUsed))
    :set_text(typeString)
  typeSubTree:add_le(ft.wbType, typeRaw)
  local dataOffset = 4
  local addr6String = ""

  -- Loop through each Address Byte
  for i = 1, 8 do
    -- Grab each pair of values
    local intValue = buffer(dataOffset,2)
    -- Append the element string
    addr6String = addr6String .. string.format("%x:",intValue:uint())
    -- Move to next element
    dataOffset = dataOffset + 2
    typeSubTree:add_le(ft.wbAddr6RefValue, intValue)
  end

  typeSubTree:append_text(addr6String:sub(1,-2))

  return bytesUsed
end

-- ╔═══════════════════════════╗
--   Element: String Reference
-- ╚═══════════════════════════╝
stringRefContent = function(typeRaw, typeHash, buffer, tree)
  local stringSize = buffer(4,1)
  local bytesUsed
  local typeIDString = getTypeIDString(typeRaw)
  local typeIndex = getIndex(typeRaw)

  -- if size of String is 0, return empty string
  if stringSize:le_uint() == 0 then
    bytesUsed = 5

    local typeString = string.format("string.%s%s = \"\"", typeIndex,
                                     typeIDString)

    local typeSubTree = tree:add(ft.wbElement,buffer(0,bytesUsed))
      :set_text(typeString)

    typeSubTree:add_le(ft.wbType, typeRaw)
    typeSubTree:add_le(ft.wbStringRefValue, "")
    return bytesUsed
  end

  local value = buffer(5,stringSize:le_uint())

  bytesUsed = 5 + stringSize:le_uint()
  local typeString = string.format("string.%s%s = \"%s\"", typeIndex,
                                   typeIDString, value:string())

  local typeSubTree = tree:add(ft.wbElement,buffer(0,bytesUsed))
    :set_text(typeString)

  typeSubTree:add_le(ft.wbType, typeRaw)
  typeSubTree:add_le(ft.wbStringRefValue, value)
  return bytesUsed
end

-- ╔═════════════════════════════════╗
--   Element: UINT32 Array Reference
-- ╚═════════════════════════════════╝
u32ArrayRefContent = function(typeRaw, typeHash, buffer, tree)
  local vectorSize = buffer(4,2)
  local typeIDString = getTypeIDString(typeRaw)
  local typeIndex = getIndex(typeRaw)
  -- Each item is a 4 Byte DWORD, so multiply the number
  -- of elements by 4
  value = buffer(6,vectorSize:le_uint()*4)
  local bytesUsed = 6 + (vectorSize:le_uint() * 4)

  local typeString = string.format("u32[0x%x].%s%s = {",
                                   vectorSize:le_uint(),
                                   typeIndex,
                                   typeIDString)

  local typeSubTree = tree:add(ft.wbElement,buffer(0,bytesUsed))
    :set_text(typeString)

  typeSubTree:add_le(ft.wbType, typeRaw)
  typeSubTree:add_le(ft.wbU32ArrayElements, vectorSize)

  local dataOffset = 6
  local arrayContentString = ""
  -- Loop through each Integer value
  for i = 1, vectorSize:le_uint() do
    -- Grab the value
    local intValue = buffer(dataOffset,4)
    -- Append the element string
    arrayContentString = arrayContentString ..
      string.format("0x%x, ",intValue:le_uint())

    -- Move to next element
    dataOffset = dataOffset + 4
    typeSubTree:add_le(ft.wbU32RefValue32, intValue)
  end
  typeSubTree:append_text(arrayContentString:sub(1,-3) .. "}")

  return bytesUsed
end

-- ╔═════════════════════════════════╗
--   Element: UINT64 Array Reference
-- ╚═════════════════════════════════╝
u64ArrayRefContent = function(typeRaw, typeHash, buffer, tree)
  local arraySize = buffer(4,2)
  -- Each item is an 8 Byte QWORD, so multiply the number
  -- of elements by 8
  value = buffer(6,arraySize:le_uint()*8)
  local bytesUsed = 6 + (arraySize:le_uint() * 8)
  local typeIDString = getTypeIDString(typeRaw)
  local typeIndex = getIndex(typeRaw)

  local typeString = string.format("u64[0x%x].%s%s = %s",
                                   arraySize:le_uint(),
                                   typeIndex,
                                   typeIDString,
                                   value)
  local typeSubTree = tree:add(ft.wbElement,buffer(0,bytesUsed)):
    set_text(typeString)

  typeSubTree:add_le(ft.wbType, typeRaw)
  typeSubTree:add_le(ft.wbU64ArrayRefValue, value)
  return bytesUsed
end

-- ╔══════════════════════════════╗
--   Element: Raw Array Reference
-- ╚══════════════════════════════╝
rawRefContent = function(typeRaw, typeHash, buffer, tree)
  local bytesUsed = 0
  local value = 0
  local vectorSize = 0
  local dataOffset = 0
  local typeIndex = getIndex(typeRaw)
  local typeIDString = getTypeIDString(typeRaw)

  vectorSize, dataOffset = getVectorSize(typeRaw, buffer)

  local typeString = string.format("u8[0x%x].%s%s = {", vectorSize:le_uint(),
                                   typeIndex, typeIDString)
  local typeSubTree = tree:add(ft.wbElement,buffer(0,dataOffset +
                                                     vectorSize:le_uint()))
    :set_text(typeString)

  typeSubTree:add_le(ft.wbType, typeRaw)
  typeSubTree:add_le(ft.wbRawRefElements, vectorSize)

  local arrayContentString = ""
  -- Loop through each Integer value
  for i = 1, vectorSize:le_uint() do
    -- Grab the value
    local intValue = buffer(dataOffset,1)
    -- Append the element string
    arrayContentString = arrayContentString ..
      string.format("0x%x, ",intValue:le_uint())

    -- Move to next element
    dataOffset = dataOffset + 1
    typeSubTree:add_le(ft.wbRawRefValue, intValue)
  end

  -- Remove last comma and append right curly bracket
  typeSubTree:append_text(arrayContentString:sub(1,-3) .. "}")

  return dataOffset
end

-- ╔═════════════════════════════════╗
--   Element: String Array Reference
-- ╚═════════════════════════════════╝
stringArrayRefContent = function(typeRaw, typeHash, buffer, tree)
  local bytesUsed = 0
  local value = 0
  local vectorSize = 0
  local dataOffset = 0
  local typeIndex = getIndex(typeRaw)
  local typeIDString = getTypeIDString(typeRaw)

  vectorSize, bytesUsed = getVectorSize(typeRaw, buffer)

  -- If no string within array, just return the typeID and vectoreSize
  -- byte lengths
  if vectorSize:le_uint() == 0 then
    local typeString = string.format("string[0x%x].%s%s = {}",
                                     vectorSize:le_uint(), typeIndex,
                                     typeIDString)
    local typeSubTree = tree:add(ft.wbElement,buffer(0,bytesUsed))
      :set_text(typeString)
    typeSubTree:add_le(ft.wbType, typeRaw)
    typeSubTree:add_le(ft.wbRawRefElements, vectorSize)
    return bytesUsed
  end

  local typeString = string.format("string[0x%x].%s%s = {",
                                   vectorSize:le_uint(), typeIndex,
                                   typeIDString)
  local typeSubTree = tree:add(ft.wbElement,buffer(0,bytesUsed))
    :set_text(typeString)

  typeSubTree:add_le(ft.wbType, typeRaw)
  typeSubTree:add_le(ft.wbRawRefElements, vectorSize)

  local arrayContentString = ""
  -- Loop through each String value
  for i = 1, vectorSize:le_uint() do
    -- Grab the string size (a 2-byte field)
    local stringSize = buffer(bytesUsed,2)
    -- Append the element string add 2 for the string size field
    local value = buffer(bytesUsed + 2,stringSize:le_uint())
    arrayContentString = arrayContentString ..
      string.format("%s, ",value:string())

    -- Set pointer to next element. Add 2 for string size field
    bytesUsed = bytesUsed + 2 + stringSize:le_uint()
    typeSubTree:add_le(ft.wbStringRefValue, value)
  end

  -- Remove last comma and append right curly bracket
  typeSubTree:append_text(arrayContentString:sub(1,-3) .. "}")
  return bytesUsed
end

--------------------------------------------------------------------------------
--                           ╭─────────────────╮
--                             Message Parsers
--                           ╰─────────────────╯
--------------------------------------------------------------------------------
-- ╔══════════════════════╗
--   Remove Chunk Offsets
-- ╚══════════════════════╝
-- Returns a "clean" TVB by removing 16-bit (2 byte) chunks
--  The Chunk Offset works as follows:
--  1. Read the chunkOffset value at offset 0 in the header
--  2. If the value of the chunkOffset is less than the length
--     of the overall message data (including chunkdata bytes),
--     minus 2 (the size of the chunk and type header fields):
--     a. Extract data up to the length specified in the
--        chunkOffset field. Skip the next 2 bytes and extract
--        data up to the next chunkOffset field, repeat.
--  3. Returns either the original message or a "clean" one
--     depending on if chunk value extraction was necessary
function removeChunkOffsetBytes(buffer)
  local chunkOffset = buffer(OFFSET_CHUNKFIELD,LEN_CHUNKFIELD):uint()
  local messageLength = buffer():len()
  --print("[removeChunk] Starting Chunk Removal. Buffer Received:")
  --hexDump(0, buffer(0))

  messageLength = buffer:len() - (LEN_CHUNKFIELD + LEN_TYPEFIELD)

  if chunkOffset < messageLength then
    local cleanedBuffer = ByteArray.new()
    local bufferIndex = 0 -- Skip chunkOffset and type byte
    local output = ""

    local i = 0
    while bufferIndex+chunkOffset < messageLength do
      if bufferIndex == 0 then
        -- Grab all bytes up to the first chunkOffset data location on the first
        -- loop, add 2 bytes to the range to account for the chunkOffset and
        -- type fields
        cleanedBuffer:append(buffer(bufferIndex, chunkOffset +
                                      LEN_CHUNKFIELD + LEN_TYPEFIELD):bytes())
        -- The bufferIndex points to the location in the raw buffer just after
        -- the chunk data that was not appended to the "cleanBuffer"
        bufferIndex = chunkOffset +
          (LEN_CHUNKFIELD + LEN_TYPEFIELD + LEN_CHUNKDATA)
      else
        -- Subsequent runs do not need to account for the header fields
        cleanedBuffer:append(buffer(bufferIndex, chunkOffset):bytes())
        -- The bufferIndex points to the location in the raw buffer just after
        -- the chunk data that was not appended to the "cleanBuffer"
        bufferIndex = bufferIndex + chunkOffset + LEN_CHUNKDATA
      end
      i = i + 1
    end

    -- Append any remaining bytes to the cleaned buffer after skipping last
    -- chunk data value
    if bufferIndex ~= cleanedBuffer:len() then
      cleanedBuffer:append(buffer(bufferIndex):bytes())
    end

    -- Add cleaned buffer to data window
    local tvb = ByteArray.tvb(cleanedBuffer, "Winbox Message (Chunks Removed)")

    return tvb
  else
    local tvb = ByteArray.tvb(buffer:bytes(), "Winbox Message")
    return tvb
  end
end

-- ╔════════════════════════════╗
--   Element: Message Reference
-- ╚════════════════════════════╝
--[[ Message Reference Header
  -- Differs slightly from "nested messages" in that this is just a single
  -- message where the message length field size is calculated using a bitmask
  -- (i.e. the getVectorSize function)
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |  Variable Message Length (LE) |             Magic             |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
]]
msgRefContent = function(typeRaw, typeHash, buffer, tree)
  local numberOfElements = 0
  local typeString = ""
  local bytesUsed = 0
  local messageSize = 0
  local totalMessageSize = 0
  local typeIndex = getIndex(typeRaw)
  local typeIDString = getTypeIDString(typeRaw)

  messageSize, bytesUsed = getVectorSize(typeRaw, buffer)
  --print(string.format("typeID: 0x%x, MessageSize: 0x%x",
  --                    typeRaw:le_uint(), messageSize:le_uint()))


  local msgTree = tree:add(Winbox_Protocol_TCP,buffer(0,messageSize:le_uint() +
                                                     bytesUsed),
                           "Winbox Message"):set_text("Winbox Message")

  -- Add raw TypeID to tree output
  msgTree:add_le(ft.wbType, typeRaw)

  -- Determine how many bytes were used to calculate the size
  if bytesUsed == 6 then
    -- subtract 1 to include size field in message header
    headerTree = msgTree:add(ft.wbMessageHeader,buffer(bytesUsed-2,4),
                             "Message Headers"):set_text("Message Headers")
  else
    headerTree = msgTree:add(ft.wbMessageHeader,buffer(bytesUsed-1,3),
                             "Message Headers"):set_text("Message Headers")
  end

  -- Add messageLength to tree output
  headerTree:add_le(ft.wbMessageLength, messageSize)
  -- Magic Bytes "M2"
  headerTree:add(ft.wbMagicBytes, buffer(bytesUsed, 2))


  -- Magic bytes are included in the messageSize
  local dataStartOffset = bytesUsed + LEN_MAGICFIELD
  bytesUsed = dataStartOffset

  local bufferPointer = 0
  -- Loop through the packet data and apply each type
  while bufferPointer < messageSize:le_uint() - LEN_MAGICFIELD do
    -- Calculate hash of the current Winbox Type
    local typeRaw  = buffer(dataStartOffset + bufferPointer, 4)
    local typeHash = band(typeRaw:le_uint(), 0xf8000000)

    -- Get the content for each type found
    local getContent = contentFunctions[unsign(typeHash)]
    local bytesUsed = getContent(
      typeRaw, typeHash, buffer(dataStartOffset+bufferPointer), msgTree
    )

    -- Increment the buffer pointer after each content retrieval
    bufferPointer = bufferPointer + bytesUsed
    numberOfElements = numberOfElements + 1
  end
  -- Add element count for tree display
  local elementDisplayString = string.format(" (Elements: %d)",
                                             numberOfElements)

  msgTree:append_text(elementDisplayString)
  return bytesUsed + bufferPointer
end

-- ╔══════════════════════════════╗
--   Parse Nested Winbox Messages
-- ╚══════════════════════════════╝
--[[ Nested Message Header
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |      Message Length (LE)      |             Magic             |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
]]
function parseNestedWinboxMessage(buffer, tree)
  local numberOfElements = 0
  local bytesUsed = buffer(0,2)

  local headerTree = tree:add(ft.wbMessageHeader,buffer(0,4),"Message Headers")
    :set_text("Message Headers")

  -- Message length is Little Endian for "nested" messages
  headerTree:add_le(ft.wbMessageLength, bytesUsed)
  -- Add 2 to compensate for the length bytes
  local bytesUsedInt = bytesUsed:le_uint()+2

  -- Magic Bytes "M2"
  headerTree:add(ft.wbMagicBytes, buffer(2, 2))

  -- Data starting after "M2" Magic
  local dataStartOffset = 4

  local bufferPointer = 0
  -- Loop through the packet data and apply each type
  while bufferPointer < bytesUsedInt-4 do
    -- Calculate hash of the current Winbox Type
    local typeRaw  = buffer(dataStartOffset + bufferPointer, 4)
    local typeHash = band(typeRaw:le_uint(), 0xf8000000)

    -- Get the content for each type found
    local getContent = contentFunctions[unsign(typeHash)]
    local bytesUsed = getContent(
      typeRaw, typeHash, buffer(dataStartOffset+bufferPointer), tree
    )

    -- Increment the buffer pointer after each content retrieval
    bufferPointer = bufferPointer + bytesUsed
    numberOfElements = numberOfElements + 1
  end
  -- Return element count for tree display
  return numberOfElements
end

-- ╔══════════════════════════════════╗
--   Enumerate Nested Winbox Messages
-- ╚══════════════════════════════════╝
msgArrayRefContent = function(typeRaw, typeHash, buffer, tree)
  local msgCount = buffer(4,2)
  local numberOfElements

  ----------------- Call Nested Message Parsing Function Here ------------------
  -- Start bytesUsed at offset 6 (After the typeID and element count)
  local bytesUsed = 6
  -- Parse each Nested element until element count reached
  local typeString = string.format("Nested Messages[0x%x]", msgCount:le_uint())

  -- Tree is based on Winbox_Protocol_TCP so that it expands automatically
  local typeSubTree = tree:add(
    Winbox_Protocol_TCP,buffer(0,bytesUsed),typeString)

  typeSubTree:add_le(ft.wbType, typeRaw)
  typeSubTree:add_le(ft.wbMsgArrayRefElements, msgCount)

  for i = 1, msgCount:le_uint() do
    -- Nested buffer size (Add 2 to account for the size bytes)
    local cBufferSize = buffer(bytesUsed,2):le_uint()+2
    -- Nested buffer contents
    local cBuffer = buffer(bytesUsed,cBufferSize)

    -- Parse the nested message contents and append to the tree
    local typeString = string.format("Winbox Message", cBufferSize)
    local cMsgSubTree = typeSubTree:add(
      Winbox_Protocol_TCP,cBuffer,typeString)
    -- Pass the tree to the nested element so that it can be appended
    numberOfElements = parseNestedWinboxMessage(cBuffer, cMsgSubTree)
    local elementDisplayString = string.format(" (Elements: %d)",
                                               numberOfElements)

    cMsgSubTree:append_text(elementDisplayString)

    -- Add the total bytes from the message length
    bytesUsed = bytesUsed + cBufferSize
  end

  -- Return bytes used for array as well as the number of messages parsed
  -- for display purposes
  return bytesUsed, msgCount:le_uint()
end

-- ╔═════════════════════════════════╗
--   Get Applicable Parsing Function
-- ╚═════════════════════════════════╝
-- Resolve a typeID hash to parsing function
contentFunctions =
  {
    [0x0] = boolContent,
    [0x8000000] = u32RefContent,
    [0x20000000] = stringRefContent,
    [0x88000000] = u32ArrayRefContent,
    [0x10000000] = u64RefContent,
    [0x18000000] = addr6RefContent,
    [0x28000000] = msgRefContent,
    [0x30000000] = rawRefContent,
    [0xA0000000] = stringArrayRefContent,
    [0xA8000000] = msgArrayRefContent
  }


-- ╔════════════════════════════╗
--   Parse Root Winbox Messages
-- ╚════════════════════════════╝
--[[ Winbox Protocol Header
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |  Chunk Offset |  Type/Version |      Message Length (BE)      |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |             Magic             |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
]]
function parseRootWinboxMessage(bPtr, buffer,tree)
  local mainSubTree
  local headerTree
  local elementSubTree

  local totalMessageLength = buffer():len()
  -- Message length is Big Endian for "root" messages
  local messageLength = buffer(OFFSET_LENGTHFIELD, LEN_LENGTHFIELD)
  local magicBytes = buffer(OFFSET_MAGICFIELD, LEN_MAGICFIELD)

  if magicBytes:string() == "M2" then

    -- Add Message to primary tree
    mainSubTree = tree:add(Winbox_Protocol_TCP,
                           buffer(OFFSET_CHUNKFIELD, totalMessageLength),
                           "Winbox Message")

    -- Add Header tree under Message tree
    headerTree = mainSubTree:add(ft.wbMessageHeader,buffer(
                                   OFFSET_CHUNKFIELD, LEN_HEADER),
                                 "Message Headers"):set_text("Message Headers")

    -- Add Header fields to Header tree
    headerTree:add(ft.chunkOffset, buffer(OFFSET_CHUNKFIELD, LEN_CHUNKFIELD))
    headerTree:add_le(ft.wbType, buffer(OFFSET_TYPEFIELD, LEN_TYPEFIELD))
    headerTree:add(ft.wbMessageLength, messageLength)
    headerTree:add(ft.wbMagicBytes, magicBytes)

  else
    -- If not a valid Winbox message, return nil
    return nil
  end

  -- Data remaining in the message should be for elements
  -- the size of it is the remaining data minus the header fields
  local elementDataLength = totalMessageLength - LEN_HEADER
  -- Count of nested messages (if applicable) to display in pinfo
  local nestedMessageCount = 0
  local elementCount = 0

  local elementPointer = 0
  -- Loop through the packet data and apply each type
  while elementPointer < elementDataLength do
    -- inner variable increments for each nested message (if applicable)
    local currentMessageCount = 0
    local bytesUsed = 0
    -- Calculate hash of the current Winbox TypeID
    local typeRaw  = buffer(OFFSET_DATASTART + elementPointer, LEN_TYPEID)

    -- Calculate the type using a bitmask to lookup the corresponding
    -- parsing function
    local typeHash = band(typeRaw:le_uint(), 0xf8000000)

    -- Call the correct parser for each type found
    local getContent = contentFunctions[unsign(typeHash)]

    -- Store the number of bytes used by the previous parser
    -- Also store the nested message count (if not nil)
    bytesUsed, individualNestedMessageCount = getContent(
      typeRaw, typeHash, buffer(OFFSET_DATASTART+elementPointer),
      mainSubTree)

    -- Add nested message count to overall nested message count
    if individualNestedMessageCount ~= nil then
      nestedMessageCount = nestedMessageCount + individualNestedMessageCount
    end

    -- Increment the element pointer after each content retrieval
    elementPointer = elementPointer + bytesUsed
    elementCount = elementCount + 1
  end

  -- Add element count to the root message tree item
  if elementCount > 0 then
    mainSubTree:append_text(string.format(" (Elements: %d)", elementCount))
  end
  -- Add nested message count to overall nested message count
  if nestedMessageCount > 0 then
    mainSubTree:append_text(string.format(" (Nested Messages: %d)",
                                          nestedMessageCount))
  end

  -- Returns the number of nested messages found (if any)
  return nestedMessageCount
end

-- Track packet number to determine if message count(s) should be reset
local packetNumber = 0
-- Track total Winbox messages found in same stream
local messageNumber = 0
-- Track total Nested Winbox messages found in same stream
local nestedMessageCount = 0
-- ╔════════════════════════════╗
--   Primary Dissector Function
-- ╚════════════════════════════╝
function Winbox_Protocol_TCP.dissector(buffer,pinfo,tree)
  local totalBufferLength = buffer:len()
  local bufferIndex = 0
  local remainingBufferLength = totalBufferLength

  -- This prevents the message count(s) from resetting if the same stream
  -- contains multiple nested message arrays in separate messages
  if pinfo.number ~= packetNumber then
    packetNumber = pinfo.number
    messageNumber = 0
    nestedMessageCount = 0
  end
  --print("Entire Buffer Contents:")
  --hexDump(0, buffer(0))

  -- Outer loop to loop through each message
  while remainingBufferLength > 0 do
    -- -------------------------------------------------
    -- Calculating "chunked" message Length that may include
    -- 16-bit chunks that need to be removed:
    -- -------------------------------------------------
    -- 1. Take Message Length from header field
    -- 2. Add 4 for the ChunkOffset, Type, and Length bytes (not 'M2' magic)
    -- 3. Add (2 * (messageLength/chunkOffset))
    --    3a. Be sure to subtract 4 from messageLength during this calculation
    --        because headers should not be included here

    -- Get Message Length
    local messageLength = buffer(
      bufferIndex + OFFSET_LENGTHFIELD, LEN_LENGTHFIELD):uint() +
      (LEN_HEADER - LEN_MAGICFIELD)

    -- Get Chunk Offset value
    local chunkOffset = buffer(bufferIndex +
                                 OFFSET_CHUNKFIELD, LEN_CHUNKFIELD):uint()

    -- Calculate number of expected chunks to remove
    local expectedChunks = math.floor((
        messageLength - (LEN_HEADER - LEN_MAGICFIELD)) /
        chunkOffset)

    -- Calculate actual data length of message if chunking is applied
    local chunkedMessageLength = messageLength +
      (LEN_CHUNKDATA * expectedChunks)

    -- Determine if TCP Reassembly is needed
    if chunkedMessageLength > remainingBufferLength then
      print "*************************"
      local additionalDataNeeded = chunkedMessageLength - remainingBufferLength
      print(string.format("[Dissector] Packet #: %d - Requesting additional \
        data - Requested Total Length: 0x%x",
                          pinfo.number, additionalDataNeeded))

      pinfo.desegment_len = additionalDataNeeded
      print "*************************"
      return
    end

    print("\n[Dissector] -------------------------------------")
    print(string.format("\nPacket #: %d, messageNumber: 0x%x, \
      chunkOffset: 0x%x, expectedChunks: 0x%x, messageLength: 0x%x, \
      chunkedMessageLength: 0x%x, remainingBufferLength: 0x%x, \
      bufferIndex: 0x%x", pinfo.number, messageNumber, chunkOffset,
                        expectedChunks, messageLength, chunkedMessageLength,
                        remainingBufferLength, bufferIndex))

    -- Remove any Chunk Data (if applicable) and return a TVB
    cleanedBuffer = removeChunkOffsetBytes(buffer(
                                             bufferIndex, chunkedMessageLength))

    --print("Cleaned buffer:")
    --hexDump(0,cleanedBuffer:range())

    -- Track count of nested messages for pinfo display purposes.
    -- This inner count is for each message and the outer count is an
    -- overall count for the entire stream.
    local individualNestedMessageCount = parseRootWinboxMessage(
      bufferIndex, cleanedBuffer, tree)

    if individualNestedMessageCount ~= nil then
      nestedMessageCount = nestedMessageCount + individualNestedMessageCount
    end

    -- Increment buffer index to point to next message (if applicable)
    -- Account for chunks removed in the bufferIndex calculation
    bufferIndex = bufferIndex + cleanedBuffer:len() +
      (expectedChunks * LEN_CHUNKDATA)

    -- Count number of messages (for display purposes)
    messageNumber = messageNumber + 1

    -- Loop until the entire buffer contents are consumed
    remainingBufferLength = totalBufferLength - bufferIndex
    print(string.format("Message finished parsing. Current bufferIndex: 0x%x, \
      remainingBufferLength: 0x%x", bufferIndex, remainingBufferLength))

    print("--------------------------------------[Dissector]")
  end -- Loop to next message or parsing is completed

  ------------------------------------------------------------------------------
  --   Column Display Setup
  pinfo.cols.protocol = Winbox_Protocol_TCP.name
  -- Display Root Message Count as well as Nested Message Count (if applicable)
  local elementDisplayString = ""
  if messageNumber > 0 then
    -- Allow overwriting of the information column
    pinfo.cols.info:clear_fence()

    -- Display nested message info if available
    if nestedMessageCount > 0 then
      elementDisplayString = string.format(
        "Winbox Message (Messages: %d) (Nested: %d)", messageNumber,
        nestedMessageCount)
      pinfo.cols.info:set(elementDisplayString)
    else
      pinfo.cols.info:clear()
      elementDisplayString = string.format(
        "Winbox Message (Messages: %d)", messageNumber)
      pinfo.cols.info:set(elementDisplayString)
    end
  end
end

-- ╔════════════════════╗
--   Register Dissector
-- ╚════════════════════╝
tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(8291,Winbox_Protocol_TCP)
