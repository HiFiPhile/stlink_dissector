local stlink_protocol = Proto("ST-Link",  "ST-Link Command")

local stlink_commands = {
  [0xF1] = "Get Version",
  [0xF2] = "Debug Command",
  [0xF3] = "Dfu Command",
  [0xF5] = "Get Current Mode",
  [0xF7] = "Get Target Voltage",
  [0xFB] = "Get Version Apiv3"
}

local stlink_debug_commands = {
  [0x00] = "Enter JTAG Reset",
  [0x01] = "Get status",
  [0x02] = "Force debug",

  [0x03] = "Apiv1 Reset sys",
  [0x04] = "Apiv1 Read all regs",
  [0x05] = "Apiv1 Read reg",
  [0x06] = "Apiv1 Write reg",

  [0x07] = "Read MEM 32bit",
  [0x08] = "Write MEM 32bit",
  [0x09] = "Run core",
  [0x0a] = "Step core",
  [0x0b] = "Apiv1 Set FP",
  [0x0c] = "Read MEM 8bit",
  [0x0d] = "Write MEM 8bit",
  [0x0e] = "Apiv1 Clear FP",
  [0x0f] = "Apiv1 Write debug reg",
  [0x20] = "Apiv1 Enter",

  [0x21] = "Exit",
  [0x22] = "Read core ID",

  [0x30] = "Apiv2 Enter",
  [0x31] = "Apiv2 Read ID codes",
  [0x32] = "Apiv2 Reset sys",
  [0x33] = "Apiv2 Read reg",
  [0x34] = "Apiv2 Write reg",
  [0x35] = "Apiv2 Write debug reg",
  [0x36] = "Apiv2 Read debug reg",

  [0x3A] = "Apiv2 Read all regs",
  [0x3B] = "Apiv2 Get last RW status",
  [0x3C] = "Apiv2 Drive Nrst",
  [0x3E] = "Apiv2 Get last RW status2",
  [0x40] = "Apiv2 Start Trace Rx",
  [0x41] = "Apiv2 Stop Trace Rx",
  [0x42] = "Apiv2 Get Trace Nb",
  [0x43] = "Apiv2 SWD Set Freq",

  [0x44] = "Apiv2 JTAG Set Freq",
  [0x45] = "Apiv2 Read Dap Reg",
  [0x46] = "Apiv2 Write Dap Reg",
  [0x47] = "Apiv2 Read MEM 16bit",
  [0x48] = "Apiv2 Write MEM 16bit",

  [0x4B] = "Apiv2 Init AP",
  [0x4C] = "Apiv2 Close AP Dbg",

  [0x50] = "Write MEM 32bit No Addr Inc",
  [0x51] = "Apiv2 RW Misc Out",
  [0x52] = "Apiv2 RW Misc In",

  [0x54] = "Read MEM 32bit No Addr Inc",

  [0x61] = "Apiv3 Set Com Freq",
  [0x62] = "Apiv3 Get Com Freq",

  [0xa3] = "Enter SWD",
  [0xa4] = "Enter JTAG No Reset"
}

local stlink_status_response = {
  [0x00] = "SWIM_OK",
  [0x01] = "SWIM_BUSY",
  [0x80] = "OK",
  [0x81] = "FAULT",
  [0x10] = "SWD_AP_WAIT",
  [0x11] = "SWD_AP_FAULT",
  [0x12] = "SWD_AP_ERROR",
  [0x13] = "SWD_AP_PARITY_ERROR",
  [0x09] = "JTAG_GET_IDCODE_ERROR",
  [0x0c] = "JTAG_WRITE_ERROR",
  [0x0d] = "JTAG_WRITE_VERIF_ERROR",
  [0x14] = "SWD_DP_WAIT",
  [0x15] = "SWD_DP_FAULT",
  [0x16] = "SWD_DP_ERROR",
  [0x17] = "SWD_DP_PARITY_ERROR",
  [0x18] = "SWD_AP_WDATA_ERROR",
  [0x19] = "SWD_AP_STICKY_ERROR",
  [0x1a] = "SWD_AP_STICKYORUN_ERROR",
  [0x1d] = "BAD_AP_ERROR"
}

local stlink_dev_mode = {
  [0x00] = "DFU",
  [0x01] = "MASS",
  [0x02] = "DEBUG",
  [0x03] = "SWIM",
  [0x04] = "BOOTLOADER",
  [-1] = "UNKNOWN"
}

local data_dis = Dissector.get("data")

-- Global
local cmd_field = ProtoField.uint8("stlink.cmd", "Command", base.HEX, stlink_commands)
-- Debug
local dbg_field = ProtoField.uint8("stlink.dbg", "Debug Command", base.HEX, stlink_debug_commands)

local dbg_ap_num_field = ProtoField.uint8("stlink.dbg.ap.num", "AP Number")
local dbg_is_jtag_field = ProtoField.bool("stlink.dbg.is_jtag", "JTAG")

local dbg_freq_field = ProtoField.uint16("stlink.dbg.freq", "Frequency")

local dbg_mem_addr_field = ProtoField.uint32("stlink.dbg.mem.addr", "Address", base.HEX)
local dbg_mem_length_field = ProtoField.uint16("stlink.dbg.mem.len", "Length", base.HEX)

local dbg_dap_reg_field = ProtoField.uint16("stlink.dbg.dap.reg", "Address", base.HEX)
local dbg_dap_port_field = ProtoField.uint16("stlink.dbg.dap.reg", "Port")

local dbg_reg_addr_field = ProtoField.uint32("stlink.dbg.reg.addr", "Address", base.HEX)
local dbg_reg_val_field = ProtoField.uint32("stlink.dbg.reg.val", "Value", base.HEX)

-- Response
local resp_mode_field = ProtoField.uint8("stlink.resp.mode", "Mode", base.HEX, stlink_dev_mode)
local resp_status_field = ProtoField.uint8("stlink.resp.status", "Status", base.HEX, stlink_status_response)
local resp_val_field = ProtoField.uint32("stlink.resp.val", "Value", base.HEX)
local resp_payload_field = ProtoField.bytes("stlink.resp.payload", "Payload", base.SPACE)
local resp_voltage_field = ProtoField.float("stlink.resp.voltage", "Target Voltage")


stlink_protocol.fields = {
  cmd_field, dbg_field,
  dbg_freq_field,
  dbg_mem_addr_field, dbg_mem_length_field,
  dbg_reg_addr_field, dbg_reg_val_field,
  dbg_ap_num_field, dbg_is_jtag_field,
  dbg_dap_reg_field, dbg_dap_port_field,
  resp_status_field,
  resp_payload_field,
  resp_val_field,
  resp_mode_field,
  resp_voltage_field
}

local dst_addr = nil
local cmd_cache = {}
local resp_cache = {}

local function cmd_cache_add(frame_num, cmd_id, dbg_cmd_id, last_cmd_tx)
  cmd_cache[frame_num] = {cmd_id, dbg_cmd_id, last_cmd_tx}
end

local function cmd_cache_search(frame_num)
  local limit = 100
  local count = 0

  for i = frame_num - 1, 1, -1 do
    if cmd_cache[i] then
      return cmd_cache[i]
    end
    count = count + 1
    if count >= limit then
      break
    end
  end
  return nil
end

local function resp_cache_add(frame_num, cmd_cache)
  resp_cache[frame_num] = cmd_cache
end

local function resp_cache_get(frame_num)
  return resp_cache[frame_num]
end

local function num_str(num, length)
  if num == nil then return 'nil' end
  return string.format("%0" .. length .. "X", num)
end

local function decode_cmd(buffer, pinfo, tree)
  local length = buffer:len()
  if length ~= 16 then return end

  if tostring(pinfo.src) ~= 'host' then return end

  pinfo.cols.protocol = stlink_protocol.name

  local cmd_id = buffer(0,1):uint()
  local cmd_txt = stlink_commands[cmd_id]

  if cmd_txt == nil then return end

  dst_addr = tostring(pinfo.dst)
  local dbg_cmd_id = nil
  local last_cmd_tx = false

  local subtree = tree:add(stlink_protocol, buffer())

  subtree:add(cmd_field, cmd_id)

  pinfo.cols.info:set(cmd_txt .. ' (0x' .. string.format("%02X", cmd_id) .. ')')

  -- Debug Command
  if cmd_id == 0xF2 then
    dbg_cmd_id = buffer(1,1):uint()
    local dbg_cmd_txt = stlink_debug_commands[dbg_cmd_id]

    subtree:add(dbg_field, dbg_cmd_id)

    if dbg_cmd_txt ~= nil then
      pinfo.cols.info:append(', ' .. dbg_cmd_txt .. ' (0x' .. string.format("%02X", dbg_cmd_id) .. ')')
    end

    -- Read/Write mem 32bit
    if dbg_cmd_id == 0x07 or dbg_cmd_id == 0x08 then
      if dbg_cmd_id == 0x08 then
        last_cmd_tx = true
      end
      local addr = buffer(2,4):le_uint()
      local len = buffer(6,2):le_uint()

      subtree:add(dbg_mem_addr_field, addr)
      subtree:add(dbg_mem_length_field, len)

      pinfo.cols.info:append(', Addr: 0x' .. string.format("%08X", addr) .. ', Len: 0x' .. string.format("%04X", len))

    -- Read (debug) reg
    elseif dbg_cmd_id == 0x36 or dbg_cmd_id == 0x33 or dbg_cmd_id == 0x05 then
      local addr = buffer(2,4):le_uint()

      subtree:add(dbg_reg_addr_field, addr)
      pinfo.cols.info:append(', Reg: 0x' .. string.format("%08X", addr))

    -- Write (debug/dap) reg
    elseif dbg_cmd_id == 0x35 or dbg_cmd_id == 0x0f or dbg_cmd_id == 0x34 or dbg_cmd_id == 0x06 then
      local addr = buffer(2,4):le_uint()
      local val = buffer(6,4):le_uint()

      subtree:add(dbg_reg_addr_field, addr)
      subtree:add(dbg_reg_val_field, addr)
      pinfo.cols.info:append(', Reg: 0x' .. string.format("%08X", addr) .. ', Val: 0x' ..string.format("%08X", val))

    -- Read dap reg
    elseif dbg_cmd_id == 0x45 then
      local port = buffer(2,2):le_uint()
      local addr = buffer(4,2):le_uint()

      subtree:add(dbg_dap_port_field, port)
      subtree:add(dbg_dap_reg_field, addr)
      pinfo.cols.info:append(', Port: ' .. port .. ', Reg: 0x' .. string.format("%04X", addr))

    -- Write dap reg
    elseif  dbg_cmd_id == 0x46 then
      local port = buffer(2,2):le_uint()
      local addr = buffer(4,2):le_uint()
      local val = buffer(6,4):le_uint()

      subtree:add(dbg_dap_port_field, port)
      subtree:add(dbg_dap_reg_field, addr)
      subtree:add(dbg_reg_val_field, val)
      pinfo.cols.info:append(', Port: ' .. port .. ', Reg: 0x' .. string.format("%04X", addr) .. ', Val: 0x' .. string.format("%08X", val))

    -- Apiv2 Init AP
    elseif dbg_cmd_id == 0x4b then
      local num = buffer(2,1):uint()

      subtree:add(dbg_ap_num_field, num)
      pinfo.cols.info:append(', AP: ' .. num)

    -- Get / Set com freq
    elseif dbg_cmd_id == 0x61 or dbg_cmd_id == 0x62 then
    local is_jtag = buffer(2,1):uint()

    subtree:add(dbg_is_jtag_field, is_jtag)
    pinfo.cols.info:append(', JTAG: ' .. is_jtag)
    end
  else
    -- fallback dissector that just shows the raw data.
    data_dis:call(buffer(2):tvb(), pinfo, tree)
  end

  if not pinfo.visited then
    cmd_cache_add(pinfo.number, cmd_id, dbg_cmd_id, last_cmd_tx)
    --print('Cmd - Num:' .. pinfo.number .. ' Buf:'.. tostring(buffer) .. ' Cmd:' .. num_str(cmd_id, 2) .. ' Dbg:' .. num_str(dbg_cmd_id, 2))
  end

end

local function decode_resp(buffer, pinfo, tree, last_cmd, last_dbg_cmd)
  pinfo.cols.protocol = stlink_protocol.name

  local subtree = tree:add(stlink_protocol, buffer(), 'ST-Link Response')

  -- Apiv2 Get last RW status2
  -- Apiv2 SWD/JTAG set freq
  -- Api v1/v2 enter
  -- Read/write (debug) register
  -- Apiv2 Init/close AP
  -- Apiv2 Read/write Dap register
  -- Apiv2 drive Nrst
  -- print('Resp - Visited:' .. tostring(pinfo.visited) .. ' Num:' .. pinfo.number .. ' Buf:'.. tostring(buffer) .. ' Cmd:' .. num_str(last_cmd, 2) .. ' Dbg:' .. num_str(last_dbg_cmd, 2))

  if last_dbg_cmd == 0x3e or last_dbg_cmd == 0x43 or last_dbg_cmd == 0x44 or
    last_dbg_cmd == 0x20 or last_dbg_cmd == 0x30 or
    last_dbg_cmd == 0x36 or last_dbg_cmd == 0x33 or last_dbg_cmd == 0x05 or
    last_dbg_cmd == 0x35 or last_dbg_cmd == 0x0f or last_dbg_cmd == 0x34 or last_dbg_cmd == 0x06 or
    last_dbg_cmd == 0x4b or last_dbg_cmd == 0x4c or
    last_dbg_cmd == 0x45 or last_dbg_cmd == 0x46 or last_dbg_cmd == 0x3c then

    if last_dbg_cmd ~= 0x05 then
      local status = buffer(0,1):uint()
      subtree:add(resp_status_field, status)

      local status_str = stlink_status_response[status]
      if status_str == nil then status_str = 'UNKNOWN (0x' .. string.format("%02X", status) .. ')' end
      pinfo.cols.info:set('Status: ' .. status_str)

      if status == 0x80 then
        if last_dbg_cmd == 0x05 then
          local val = buffer(0,4):le_uint()
          subtree:add(resp_val_field, val)
          pinfo.cols.info:set('Val: 0x' .. string.format("%08X", val))
        elseif last_dbg_cmd == 0x36 or last_dbg_cmd == 0x45 then
          local val = buffer(4,4):le_uint()
          subtree:add(resp_val_field, val)
          pinfo.cols.info:append(', Val: 0x' .. string.format("%08X", val))
        end
      end
    end
  -- Get com freq
  elseif last_dbg_cmd == 0x62 then
    local status = buffer(0,1):uint()
    subtree:add(resp_status_field, status)

    pinfo.cols.info:set('Status: ' .. stlink_status_response[status])
    if status == 0x80 then
      local size = buffer(8,1):uint()

      for size = 0, size - 1 do
        local val = buffer(12 + 4 * size, 2):le_uint()
        subtree:add(dbg_freq_field, val, nil, 'kHz')
        pinfo.cols.info:append(', Freq: ' .. val .. ' kHz')
      end
    end
  -- Get current mode
  elseif last_cmd == 0xf5 then
    local mode = buffer(0,1):uint()
    local mode_txt = stlink_dev_mode[mode]

    subtree:add(resp_mode_field, mode)
    pinfo.cols.info:set('Mode: ' .. mode_txt)
  -- Get target voltage
  elseif last_cmd == 0xf7 then
    local adc_results0 = buffer(0, 4):le_uint()
    local adc_results1 = buffer(4, 4):le_uint()
    local target_voltage = 0

    if adc_results0 ~= 0 then
      target_voltage = 2 * (adc_results1 * (1.2 / adc_results0))
    end

    subtree:add(resp_voltage_field, target_voltage, nil, ' V')
    pinfo.cols.info:set('Target Voltage: ' .. string.format("%.2f V", target_voltage))
  else

    subtree:add(resp_payload_field, buffer(0, buffer:len()))
    pinfo.cols.info:set('Payload: ' .. buffer:bytes():tohex())
  end

end


function stlink_protocol.dissector(buffer, pinfo, tree)
  local resp_found = false
  if dst_addr ~= nil and (tostring(pinfo.src) == dst_addr or tostring(pinfo.dst) == dst_addr) then
    local cmd = resp_cache_get(pinfo.number)
    if cmd ~= nil then
      local last_cmd = cmd[1]
      local last_dbg_cmd = cmd[2]

      decode_resp(buffer, pinfo, tree, last_cmd, last_dbg_cmd)
      resp_found = true
    else
      cmd = cmd_cache_search(pinfo.number)
      if cmd ~= nil then
        local last_cmd = cmd[1]
        local last_dbg_cmd = cmd[2]
        local last_cmd_tx = cmd[3]

        if tostring(pinfo.src) == dst_addr and not last_cmd_tx or tostring(pinfo.dst) == dst_addr and last_cmd_tx then
          resp_cache_add(pinfo.number, cmd)
          decode_resp(buffer, pinfo, tree, last_cmd, last_dbg_cmd)
          resp_found = true
        end
      end
    end
  end

  if not resp_found then
    decode_cmd(buffer, pinfo, tree)
  end
end

DissectorTable.get("usb.bulk"):add(0xff, stlink_protocol)
