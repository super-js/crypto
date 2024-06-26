import {BDKI_DUKPT_KEY_TYPE, BdkiDukpt} from "./bdki-dukpt";

describe("bdki-dukpt", () => {
    it("should create bdki dukpt", () => {
        const bdkiDukpt = new BdkiDukpt({
            keyType: BDKI_DUKPT_KEY_TYPE.TDES_KSI,
            content: '1234567812'
        });
        expect(bdkiDukpt).toBeInstanceOf(BdkiDukpt);
    })
})