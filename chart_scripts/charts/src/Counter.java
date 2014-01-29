import java.util.HashMap;
import java.util.Map;

public class Counter<X> {

	private Map<X, Integer> dictionary = null;

	public Counter() {
		this.dictionary = new HashMap<X, Integer>();
	}

	public Counter(int initialSize, float load) {
		this.dictionary = new HashMap<X, Integer>(initialSize, load);
	}

	public Counter(int initialSize) {
		this.dictionary = new HashMap<X, Integer>(initialSize);
	}

	public Map<X, Integer> getDictionary() {
		return dictionary;
	}

	public int size() {
		return dictionary.size();
	}

	public void update(X[] keys) {

		for (X s : keys) {

			if (dictionary.containsKey(s))
				dictionary.put(s, dictionary.get(s) + 1);
			else
				dictionary.put(s, 1);
		}
	}

	public void update(X key) {

		if (dictionary.containsKey(key))
			dictionary.put(key, dictionary.get(key) + 1);
		else
			dictionary.put(key, 1);

	}
}