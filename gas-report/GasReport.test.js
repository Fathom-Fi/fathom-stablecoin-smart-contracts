describe("GasReport", () => {
  beforeEach(async () => {
    await deployments.fixture(["DeployMain"]);
  });

  describe("#gas-report", () => {
    context("running this test with the sole purpose of measuring gas consumption on deployment", () => {
      it("should log gas consumption when deploying the Stablecoin protocol", async () => {});
    });
  });
});
