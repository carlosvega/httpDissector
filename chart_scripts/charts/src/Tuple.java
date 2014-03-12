public class Tuple<X extends Comparable<X>, Y> implements
		Comparable<Tuple<X, Y>> {
	private X x;
	private Y y;

	public Tuple(X x, Y y) {
		this.x = x;
		this.y = y;
	}

	X getX() {
		return x;
	}

	void setX(X x) {
		this.x = x;
	}

	Y getY() {
		return y;
	}

	void setY(Y y) {
		this.y = y;
	}

	@Override
	public int compareTo(Tuple<X, Y> o) {
		return this.getX().compareTo(o.getX());
	}
}
