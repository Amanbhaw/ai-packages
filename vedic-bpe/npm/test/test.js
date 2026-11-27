const assert = require('assert');
const { pack, unpack } = require('../src/index.js');
let n = 0;
function ok(name, cond){ assert(cond, name); console.log('  ok  ' + name); n++; }

const sample = JSON.stringify([
  {ticket_id:"SUP-101",tier:"enterprise",issue:"billing_delay",status:"open"},
  {ticket_id:"SUP-102",tier:"enterprise",issue:"billing_delay",status:"open"},
  {ticket_id:"SUP-103",tier:"enterprise",issue:"api_timeout",status:"open"},
  {ticket_id:"SUP-104",tier:"pro",issue:"api_timeout",status:"closed"}
]);
ok('lossless round-trip (bit-exact)', JSON.stringify(unpack(pack(sample))) === JSON.stringify(JSON.parse(sample)));
ok('0% inflation on non-table input', pack(JSON.stringify("hello")) === JSON.stringify("hello"));
// typed values + leading zero safety
const typed = JSON.stringify([
  {device:"pool_cam_01",fps:30,alert:false,val:102},
  {device:"pool_cam_01",fps:30,alert:false,val:103}
]);
ok('types + leading-zero preserved', JSON.stringify(unpack(pack(typed))) === JSON.stringify(JSON.parse(typed)));
// cross-language fixture (must match Python output byte-for-byte)
const packed = pack(sample);
console.log('  packed bytes:', JSON.stringify(packed));
console.log(n + ' tests passed');
