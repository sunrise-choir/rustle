const fs = require('fs').promises
const ssbkeys = require('ssb-keys')

//usually, load keys like this
var keys = ssbkeys.loadOrCreateSync("../alice/secret")
/* => {
  id: String,
  public: String,
  private: String
}*/

//hmac_key is a fixed value that applies to _THIS_ signature use, see below.

dothings(keys)
  .then(o => console.log(o))

// var obj = ssbkeys.signObj(keys, { foo: 'bar' })
// console.log(obj) /* => {
//   foo: 'bar',
//   signature: ...
// } */
// console.log(ssbkeys.verifyObj(keys, obj))

async function dothings(keys) {
  const dir = '../alice/'
  const s = await fs.readFile(dir+'about-full-from-log.json')
  let value = JSON.parse(s).value
  delete value.signature

  let tosign = JSON.stringify(value, null, 2)
  console.log(tosign)

  await fs.writeFile(dir+'about-value-to-sign.json', tosign)

  let signed = JSON.stringify(ssbkeys.signObj(keys, value), null, 2)
  console.log(signed)

  await fs.writeFile(dir+'about-value-to-verify.json', signed)
}
