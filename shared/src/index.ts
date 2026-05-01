export type TradeSide = "buy" | "sell";

export interface PlaceTradeArgs {
  symbol: string;
  side: TradeSide;
  quantity: number;
  limit: number;
}

export interface PlaceTradeResult {
  success: true;
  tradeId: string;
  executedAt: string;
}

export interface TradeRecord extends PlaceTradeArgs {
  tradeId: string;
  executedAt: string;
}
