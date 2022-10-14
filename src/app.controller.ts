import { Controller, Get } from "@nestjs/common";
import { AppService } from "./app.service";

@Controller("coin")
export class AppController {
    constructor(private readonly appService: AppService) {}

    // @Get('/iota')
    // async getIotaAddress() {
    //   return this.appService.getIotaAddress();
    // }

    @Get("/iota")
    async getIotaAddress() {
        return this.appService.getIotaAddress();
    }
    @Get("/atom")
    async getAtomAddress() {
        return this.appService.getAtomAddress();
    }

    @Get("/doge")
    async getDogeAddress() {
        return this.appService.getDogeAddress();
    }
    @Get("/bch")
    async getBchAddress() {
        return this.appService.getBchAddress();
    }

    @Get("/btc")
    async getBtcAddress() {
        return this.appService.getBtcAddress();
    }

    @Get("/erc20")
    async getErc20Address() {
        return this.appService.getErc20Address();
    }

    @Get("/xrp")
    async getXrpAddress() {
        return this.appService.getXrpAddress();
    }

    @Get("/theta")
    async getThetaAddress() {
        return this.appService.getThetaAddress();
    }

    @Get("/xlm")
    async getStellarAddress() {
        return this.appService.getStellarAddress();
    }

    @Get("ltc")
    async getLitecoinAddress() {
        return this.appService.getLitecoinAddress();
    }

    @Get("/trx")
    async getTronAddress() {
        return this.appService.getTronAddress();
    }

    @Get("/ada")
    async getCardanoAddress() {
        return this.appService.getCardanoAddress();
    }

    @Get("/sol")
    async getSolanaAddress() {
        return this.appService.getSolanaAddress();
    }

    @Get("/dot")
    async getPolkadotAddress() {
        return this.appService.getPolkadotAddress();
    }

    @Get("/cro")
    async getCryptoComAddress() {
        return this.appService.getCryptoComAddress();
    }

    @Get("/algo")
    async getAlgoAddress() {
        return this.appService.getAlgoAddress();
    }

    @Get("/hbar")
    async getHbarAddress() {
        return this.appService.getHbarAddress();
    }
}
