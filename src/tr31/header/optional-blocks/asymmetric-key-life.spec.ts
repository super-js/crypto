import {ASYMMETRIC_KEY_LIFE, AsymmetricKeyLife} from "./asymmetric-key-life";

describe("asymmetric-key-life", () => {
    it("should create asymmetric key life", () => {
        const asymmetricKeyLife = new AsymmetricKeyLife({
            asymmetricKeyLife: ASYMMETRIC_KEY_LIFE.EPHEMERAL
        });

        expect(asymmetricKeyLife).toBeInstanceOf(AsymmetricKeyLife);
    })
})