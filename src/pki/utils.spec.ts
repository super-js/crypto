import {KEYUTIL} from "jsrsasign";

describe("CryptoUtils", () => {
    it('should work', () => {

        console.log(KEYUTIL.getKey(`-----BEGIN PRIVATE KEY-----
MIG/AgEAMBAGByqGSM49AgEGBSuBBAAiBIGnMIGkAgEBBDCQ0jtEMqcZGQ4vJfSA
qJBKRcs0DIj3d1lW9n+qGxvzow8chB+t2blQSUKI+dZBnV+gBwYFK4EEACKhZANi
AASkliJTBiK1oaCEstUpJ5sxT6OQvzz/80sJkNcgPSq1VmiZHBadYJ1Ki/tmE2aL
ta+9tGl5CAjwhubD/O8boO4GxKdjteE2yL+YREcAV82nZEaR8SoPz09DxsGl6NjN
YBc=
-----END PRIVATE KEY-----`));
    })
})