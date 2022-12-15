package vault.client;

public class CipheredUserPointList {
    public CipheredUserPoint[] userPoints;
    public CipheredUserPointList(int size) {
        userPoints = new CipheredUserPoint[size];
    }
}
