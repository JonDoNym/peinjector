#!/usr/bin/env python
# -*- encoding: utf-8 -*-

"""
    Provides de-serialization and in-stream patch applying capabilities for PE Files
"""

__author__ = 'A.A.'

# Unpack binary data
from struct import unpack_from


# Holds an single patch part
class PePatchPart(object):
    # Constructor
    def __init__(self, mem, position, insert):
        self.mem = mem
        self.next = None
        self.position = position
        self.insert = insert
        self.finished = False


# Deserialize and applies patches on pe files
class PePatch(object):

    # Sentinel size
    pepatch_sentinelsize = 9;

    # First Patch part
    first = None

    # Constructor
    def __init__(self, serialized_memory):
        serialized_mem_size = len(serialized_memory)
        current_position = 0
        current = None
        patch = None

        # Deserialize data
        while (serialized_mem_size - current_position) >= self.pepatch_sentinelsize:
            mem_size, position, insert = unpack_from("<II?", serialized_memory, current_position)
            # 2*sizeof(uint32_t) + sizeof(uint8_t)
            current_position += 9

            # Length Error
            if (serialized_mem_size - current_position) < mem_size:
                return

            # Extract Data
            patch_data = serialized_memory[current_position:current_position + mem_size]

            # Change Position
            current_position += mem_size

            # Add Patch
            if mem_size > 0:
                patch = PePatchPart(patch_data, position, insert)
            else:
                patch = None
                
            # Build chain
            if current is not None:
                current.next = patch
            if self.first is None:
                self.first = patch
            current = patch

        # Length Error
        if (serialized_mem_size - current_position) > 0:
            self.first = None
            return

    # Patch is ok
    def patch_ok(self):
        return self.first is not None

    # Apply patch on stream data
    def apply_patch(self, mem, position):
        all_finished = True
        
        # Nothing to patch
        if self.first is None:
            return mem

        # Apply each patch part
        current = self.first
        while current is not None:
            # Finished, no need to check
            if current.finished:
                current = current.next
                continue
            
            # Patch starts inside memory
            if position <= current.position < (position + len(mem)):
                delta_position = current.position - position
                # Insert
                if current.insert:
                    mem = mem[:delta_position] + current.mem + mem[delta_position:]
                    
                    # Patch part finished
                    current.finished = True
                
                # Overwrite
                else:
                    mem = mem[:delta_position] + current.mem[:len(mem)-delta_position] \
                        + mem[delta_position+len(current.mem):]

                # Patch applied
                all_finished = False 
            
            # Append after current mem part (important if current part is the last part)
            elif current.insert and (current.position == (position + len(mem))):
                # Append patch
                mem = mem + current.mem
                
                # Patch part finished
                current.finished = True
            
                # Patch applied
                all_finished = False 
                
            # Patch starts before memory
            elif (not current.insert) and ((current.position + len(current.mem)) > position)\
                    and (current.position < position):
                delta_position = position - current.position
                mem = current.mem[delta_position:delta_position+len(mem)] + mem[len(current.mem)-delta_position:]
                
                # Patch applied
                all_finished = False 
            
            # Patch finished
            elif (current.position + len(current.mem)) < position:
                current.finished = True
            
            # Reset total finished  
            else:
                # Patch waiting
                all_finished = False
            
            # Next patch part     
            current = current.next
        
        # Patch finished
        if all_finished:
            self.first = None
        
        # Return patched memory
        return mem
