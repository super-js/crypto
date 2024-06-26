import {Tr31Data} from "./tr-31-data";
import {AesCmac} from "../../utils";

describe("tr-31-data", function () {
    it("should create data block", () => {
        const tr31Data = new Tr31Data({
            aesCmac: new AesCmac(Buffer.alloc(16,0))
        }).setData(Buffer.alloc(32, 0))
        expect(tr31Data).toBeInstanceOf(Tr31Data);

    });
});