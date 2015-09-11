package eu.peinjector.libpe;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * <p>Provides de-serialization and in-stream patch applying capabilities for PE Files</p>
 * <pre>
 *     +---------------------------------------------+
 *     |                 PATCH PART                  |
 *     +---------------------------------------------+       
 *     |                                             |       
 *     | +---------+----------+--------+-----------+ |       
 *     | | MEMSIZE | POSITION | INSERT | PATCH-MEM | |       
 *     | +-----------------------------------------+ |       
 *     | | uint32  |  uint32  | uint8  | MEMSIZE   | | 
 *     | | (4bit)  |  (4bit)  | (1bit) | (n bit)   | |
 *     | +         +          +        +           + |       
 *     |                                             |       
 *     +---------------------------------------------+       
 *            |                                                     
 *            v                                                     
 *     +------------+------------+------------+----    +-----------+      
 *     | PATCH PART | PATCH PART | PATCH PART | .....  | 000000000 |    
 *     +------------+------------+------------+----    +-----------+  
 * 
 *     MEMSIZE: the size of the PATCH-MEM feld
 *     POSITION: the position of this PATCH PART in the stream
 *     INSERT: 0 ... override the bytes in the stream
 *             1 ... insert new bytes in the stream
 * </pre>
 * 
 * @see LibPeDataProtocol
 */
public class LibPePatch {

	
	// Class variables
	// ------------------------------------------------------------------------------
	/** 
	 * <p>Sentinel size: The min size of a valid PATCH PART<br>
	 * 4bit MEMSIZE + 4bit POSITION + 1bit INSERT</p>
	 * 
	 * <p>000000000 == END of the PATCH (last PATCH PART)</p>
	 */
	private final static int PEPATCH_SENTINELSIZE = 9;

	/** 
	 * First part of patch chain 
	 */
	private PatchPart first = null;

	
	// Constructors
	// ------------------------------------------------------------------------------
	/**
	 * Create a new {@link LibPePatch} object with a serialized patch
	 * @param serializedPatch
	 */
	public LibPePatch(byte[] serializedPatch) {
		if(null == serializedPatch) {
			serializedPatch = new byte[0];
		}
		
		int position = 0;
		byte[] patch_mem;
		int patch_memsize = 0;
		int patch_position = 0;
		boolean patch_insert = false;
		PatchPart current = null;
		PatchPart patch = null;

		/* Deserialize data */
		while ((serializedPatch.length - position) >= LibPePatch.PEPATCH_SENTINELSIZE) {
			patch_memsize = byte2int(serializedPatch, position);
			patch_position = byte2int(serializedPatch, position + 4);
			patch_insert = (serializedPatch[position + 8] != 0);
			position += 9;

			/* Length Error */
			if ((serializedPatch.length - position) < patch_memsize) {
				first = null;
				return;
			}

			/* Add patch */
			if (patch_memsize > 0) {
				patch_mem = new byte[patch_memsize];
				System.arraycopy(serializedPatch, position, patch_mem, 0,
						patch_memsize);
				patch = new PatchPart(patch_mem, patch_position, patch_insert);
			} else {
				patch = null;
			}

			/* Change position */
			position += patch_memsize;

			/* Build chain */
			if (current != null) {
				current.next = patch;
			}
			if (this.first == null) {
				this.first = patch;
			}
			current = patch;
		}

		/* Length Error */
		if ((serializedPatch.length - position) > 0) {
			first = null;
			return;
		}
	}

	
	// public methods
	// ------------------------------------------------------------------------------
	/**
	 *  <p>Applied patch on received bytes</p>
	 *  
	 *  <p><u>Attention:</u> the manipulated block may be larger than the old one</p>
	 *  
	 *  @param mem the received part of the pe-file
	 *  @param position the position of mem[0] in the pe-file
	 */
	public byte[] applyPatch(byte[] mem, int position) {
		if(null == mem) {
			mem = new byte[0];
		}
		
		byte[] new_mem = mem;
		byte[] insert_mem = null;
		PatchPart current = this.first;
		int delta_position;
		boolean all_finished = true;

		/* Nothing to do */
		if (current == null) {
			return new_mem;
		}

		/* For each patch part */
		while (current != null) {

			/* Finished, no need to check */
			if (current.finished) {
				current = current.next;
				continue;
			}

			/* start position of current patch part in stream memory */
			if ((current.position >= position)
					&& (current.position < (position + new_mem.length))) {
				/* delta memory position */
				delta_position = current.position - position;

				/* Insert memory */
				if (current.insert) {
					insert_mem = new byte[new_mem.length + current.mem.length];
					/* Insert old memory */
					System.arraycopy(new_mem, 0, insert_mem, 0, delta_position);
					System.arraycopy(new_mem, delta_position, insert_mem,
							delta_position + current.mem.length, new_mem.length
									- delta_position);

					/* Insert patch */
					System.arraycopy(current.mem, 0, insert_mem,
							delta_position, current.mem.length);

					/* Set new memory */
					new_mem = insert_mem;

					/* Patch part finished */
					current.finished = true;

					/* Overwrite */
				} else {
					System.arraycopy(
							current.mem,
							0,
							new_mem,
							delta_position,
							min(current.mem.length, new_mem.length
									- delta_position));
				}

				/* Patch applied */
				all_finished = false;

				/*
				 * Append after current mem part (important if current part is
				 * the last part)
				 */
			} else if (current.insert
					&& (current.position == (position + new_mem.length))) {
				insert_mem = new byte[new_mem.length + current.mem.length];
				/* Insert old memory */
				System.arraycopy(new_mem, 0, insert_mem, 0, new_mem.length);
				/* Insert patch */
				System.arraycopy(current.mem, 0, insert_mem, new_mem.length,
						current.mem.length);

				/* Set new memory */
				new_mem = insert_mem;

				/* Patch part finished */
				current.finished = true;

				/* Patch applied */
				all_finished = false;

				/*
				 * end position of current patch part in stream memory or patch
				 * part bigger than stream memory
				 */
			} else if (!current.insert
					&& ((current.position + current.mem.length) > position)
					&& (current.position < position)) {
				/* delta memory position */
				delta_position = position - current.position;
				System.arraycopy(
						current.mem,
						delta_position,
						new_mem,
						0,
						min(current.mem.length - delta_position, new_mem.length));

				/* Patch applied */
				all_finished = false;

				/* Patch finished */
			} else if ((current.position + current.mem.length) < position) {
				current.finished = true;

				/* Reset total finished */
			} else {
				/* Patch waiting */
				all_finished = false;
			}

			/* Next patch part */
			current = current.next;
		}

		/* Patch finished */
		if (all_finished) {
			this.first = null;
		}

		return new_mem;
	}

	
	// private methods
	// ------------------------------------------------------------------------------
	/** 
	 * @return min(a,b) 
	 */
	private int min(int a, int b) {
		return (a < b) ? a : b;
	}

	/**
	 *  Makes Integer from byte-array at given offset 
	 */
	private int byte2int(byte[] data, int position) {
		return ByteBuffer.wrap(data,position,4).order(ByteOrder.LITTLE_ENDIAN).getInt();
	}
	
	
	// inner class
	// ------------------------------------------------------------------------------
	/** 
	 * inner class to manage a PATCH PART
	 * 
	 * @see LibPePatch
	 */
	private class PatchPart {
		byte[] mem;
		int position;
		boolean insert;
		PatchPart next;
		boolean finished;

		PatchPart(byte[] mem, int position, boolean insert) {
			this.mem = mem;
			this.position = position;
			this.insert = insert;
			this.finished = false;
		}

	}
	
}
