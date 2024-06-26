import {TDEADuktptId} from "./tdea-dukpt-id";

describe("tdea-dukpt-id", () => {
    it("should create TDEADuktptId", () => {
        const tdeaDuktptId = new TDEADuktptId({
            keySetId: '1234567890',
            deviceId: '12345'
        });

        expect(tdeaDuktptId).toBeInstanceOf(TDEADuktptId);
    })
})